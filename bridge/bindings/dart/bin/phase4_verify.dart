// Verifies the Phase 1-4 stego/FEC bindings through dart:ffi.
//   dart run bin/phase4_verify.dart [path-to-libcryptolib_c.dylib]
// Exits non-zero on any failure.
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

int _failures = 0;
void check(bool ok, String label) {
  stdout.writeln('${ok ? "  ok  " : " FAIL "} $label');
  if (!ok) _failures++;
}

void writeNoisePpm(String path, int w, int h, int seed) {
  final head = 'P6\n$w $h\n255\n'.codeUnits;
  final body = Uint8List(w * h * 3);
  var s = seed == 0 ? 1 : seed;
  for (var i = 0; i < body.length; i++) {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    body[i] = s & 0xFF;
  }
  final f = File(path).openSync(mode: FileMode.write);
  f.writeFromSync(head);
  f.writeFromSync(body);
  f.closeSync();
}

bool eq(Uint8List a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void main(List<String> args) {
  final path =
      args.isNotEmpty ? args[0] : 'build/release/libcryptolib_c.dylib';
  final lib = CryptoLib.load(path);
  lib.init();
  final dir = Directory.systemTemp.createTempSync('cl_p4_');

  // 1. Keyed stego round-trip + wrong key.
  {
    final cover = '${dir.path}/c1.ppm', out = '${dir.path}/o1.ppm';
    writeNoisePpm(cover, 256, 256, 0xC0FFEE);
    final key = Uint8List.fromList(List.filled(32, 0x5a));
    final payload = Uint8List.fromList('keyed stego via Dart'.codeUnits);
    lib.stegoEmbedKeyed(cover, payload, out, key);
    final got = lib.stegoExtractKeyed(out, key);
    check(eq(got, payload), 'keyed stego round-trip');
    var threw = false;
    try {
      lib.stegoExtractKeyed(out, Uint8List.fromList(List.filled(32, 0x99)));
    } catch (_) {
      threw = true;
    }
    check(threw, 'keyed stego wrong-key rejected');
  }

  // 2. Always-encrypt round-trip + wrong key.
  {
    final cover = '${dir.path}/c2.ppm', out = '${dir.path}/o2.ppm';
    writeNoisePpm(cover, 256, 256, 0xBEEF);
    final key = Uint8List.fromList(List.filled(32, 0x11));
    final secret = Uint8List.fromList('never in the clear'.codeUnits);
    lib.stegoEmbedEncrypted(cover, secret, out, key);
    final got = lib.stegoExtractDecrypt(out, key);
    check(eq(got, secret), 'always-encrypt round-trip');
    var threw = false;
    try {
      lib.stegoExtractDecrypt(out, Uint8List.fromList(List.filled(32, 0x22)));
    } catch (_) {
      threw = true;
    }
    check(threw, 'always-encrypt wrong-key rejected');
  }

  // 3. PhysicalSeal round-trip + wrong AAD.
  {
    final keyMedia = '${dir.path}/k3.ppm';
    final cover = '${dir.path}/c3.ppm', out = '${dir.path}/o3.ppm';
    writeNoisePpm(keyMedia, 64, 64, 0xABCDEF);
    writeNoisePpm(cover, 256, 256, 0x123456);
    final msg = Uint8List.fromList('the photo is the key'.codeUnits);
    final aad = Uint8List.fromList('dart-ctx'.codeUnits);
    lib.physicalSeal(keyMedia, msg, aad, cover, out);
    final got = lib.physicalOpen(keyMedia, aad, out);
    check(eq(got, msg), 'PhysicalSeal round-trip');
    var threw = false;
    try {
      lib.physicalOpen(keyMedia, Uint8List.fromList('wrong'.codeUnits), out);
    } catch (_) {
      threw = true;
    }
    check(threw, 'PhysicalSeal wrong-AAD rejected');
  }

  // 4. FEC single-flip correction for all three schemes.
  {
    final data = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);
    for (final scheme in [1, 2, 3]) {
      final enc = lib.fecEncode(data, scheme);
      enc[0] ^= 0x40; // one bit flip in the first block
      final dec = lib.fecDecode(enc, scheme, data.length);
      check(eq(dec, data), 'FEC scheme $scheme corrects a single flip');
    }
  }

  dir.deleteSync(recursive: true);
  stdout.writeln(_failures == 0
      ? 'ALL PASS'
      : '$_failures FAILURE(S)');
  exit(_failures == 0 ? 0 : 1);
}
