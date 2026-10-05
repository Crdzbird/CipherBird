// Verifies the Phase 1-4 stego/FEC bindings through dart:ffi.
//   dart run bin/phase4_verify.dart [path-to-libcryptolib_c.dylib]
// Exits non-zero on any failure.
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';

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
  final path = args.isNotEmpty ? args[0] : null;
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
    lib.physicalSeal(
      keyMediaPath: keyMedia,
      plaintext: msg,
      aad: aad,
      coverPath: cover,
      outputPath: out,
    );
    final got = lib.physicalOpen(
      keyMediaPath: keyMedia,
      aad: aad,
      stegoPath: out,
    );
    check(eq(got, msg), 'PhysicalSeal round-trip');
    var threw = false;
    try {
      lib.physicalOpen(
        keyMediaPath: keyMedia,
        aad: Uint8List.fromList('wrong'.codeUnits),
        stegoPath: out,
      );
    } catch (_) {
      threw = true;
    }
    check(threw, 'PhysicalSeal wrong-AAD rejected');
  }

  // 4. FEC single-flip correction for all three schemes.
  {
    final data = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]);
    for (final scheme in [
      FecScheme.repetition3,
      FecScheme.repetition5,
      FecScheme.hamming74,
    ]) {
      final enc = lib.fecEncode(data, scheme);
      enc[0] ^= 0x40; // one bit flip in the first block
      final dec = lib.fecDecode(enc, scheme, data.length);
      check(eq(dec, data), 'FEC ${scheme.name} corrects a single flip');
    }
  }

  // 5. Carrier analysis: validity, tamper digest, hidden-data probe.
  {
    final cover = '${dir.path}/a.ppm', stego = '${dir.path}/as.ppm';
    writeNoisePpm(cover, 128, 128, 0x99);
    final insp = lib.stegoInspect(cover);
    check(
      insp.parses && insp.extensionMatches && insp.width == 128,
      'inspect valid PPM',
    );

    final d1 = lib.stegoContentDigest(cover);
    File(cover).writeAsBytesSync([0], mode: FileMode.append);
    final d2 = lib.stegoContentDigest(cover);
    check(!lib.secureEqual(d1, d2), 'content digest changes on tamper');

    writeNoisePpm(cover, 128, 128, 0x99);
    lib.stegoEmbed(cover, Uint8List.fromList('hi'.codeUnits), stego);
    final rep = lib.stegoDetectHidden(stego);
    check(
      rep.cryptolibPayload && rep.note.isNotEmpty,
      'detect unkeyed cryptolib payload + honesty note',
    );
  }

  // 6. ImageFactorSeal (C2)
  {
    final img = '${dir.path}/ref.ppm',
        cover = '${dir.path}/ifs_cover.ppm',
        out = '${dir.path}/ifs_out.ppm';
    writeNoisePpm(img, 64, 64, 0xFEED);
    writeNoisePpm(cover, 256, 256, 0xCAFE);
    final seed = Uint8List.fromList(List.filled(32, 0x42));
    final msg = Uint8List.fromList('image is the second factor'.codeUnits);
    lib.imageFactorSeal(
      oprfSecretSeed: seed,
      referenceImagePath: img,
      plaintext: msg,
      coverPath: cover,
      outputPath: out,
    );
    final got = lib.imageFactorOpen(
      oprfSecretSeed: seed,
      referenceImagePath: img,
      stegoPath: out,
    );
    check(eq(got, msg.toList()), 'ImageFactorSeal round-trip');
    final other = '${dir.path}/ref2.ppm';
    writeNoisePpm(other, 64, 64, 0xBEEF);
    var threw = false;
    try {
      lib.imageFactorOpen(
        oprfSecretSeed: seed,
        referenceImagePath: other,
        stegoPath: out,
      );
    } catch (_) {
      threw = true;
    }
    check(threw, 'ImageFactorSeal wrong-image rejected');
  }

  // 7. HpkeStegoSeal (C3)
  {
    final cover = '${dir.path}/hss_cover.ppm', out = '${dir.path}/hss_out.ppm';
    writeNoisePpm(cover, 256, 256, 0x4321);
    final recip = lib.hpkeKeygen();
    final info = Uint8List.fromList('session'.codeUnits);
    final msg = Uint8List.fromList('one session keys both'.codeUnits);
    final enc = lib.hpkeStegoSeal(
      recipientPublic: recip.publicKey,
      plaintext: msg,
      info: info,
      coverPath: cover,
      outputPath: out,
    );
    final got = lib.hpkeStegoOpen(
      recipientSecret: recip.secretKey,
      enc: enc,
      info: info,
      stegoPath: out,
    );
    check(eq(got, msg.toList()), 'HpkeStegoSeal round-trip');
    final mallory = lib.hpkeKeygen();
    var threw = false;
    try {
      lib.hpkeStegoOpen(
        recipientSecret: mallory.secretKey,
        enc: enc,
        info: info,
        stegoPath: out,
      );
    } catch (_) {
      threw = true;
    }
    check(threw, 'HpkeStegoSeal wrong-recipient rejected');
  }

  // 8. HMAC-DRBG handle (A3)
  {
    final seed = Uint8List.fromList(List.filled(32, 0x01));
    final d1 = lib.drbg(
      seed,
      personalization: Uint8List.fromList('beacon'.codeUnits),
    );
    final a = d1.generate(64);
    final b = d1.generate(64);
    check(!eq(a, b), 'DRBG successive blocks differ');
    final d2 = lib.drbg(
      seed,
      personalization: Uint8List.fromList('beacon'.codeUnits),
    );
    check(eq(a, d2.generate(64)), 'DRBG reproducible from same seed');
    d1.close();
    d2.close();
    var threw = false;
    try {
      lib.drbg(Uint8List.fromList([1, 2, 3]));
    } catch (_) {
      threw = true;
    }
    check(threw, 'DRBG short-entropy rejected');
  }

  // 9. Fortuna handle (A5)
  {
    final f = lib.fortuna();
    var threw = false;
    try {
      f.generate(32);
    } catch (_) {
      threw = true;
    }
    check(threw, 'Fortuna unseeded generate rejected');
    for (var i = 0; i < 40; i++) {
      f.addEntropy(i & 7, Uint8List.fromList(List.filled(16, i)));
    }
    f.reseed();
    check(f.reseedCount() >= 1, 'Fortuna reseed count advances');
    check(f.generate(64).length == 64, 'Fortuna generate after seeding');
    f.close();
  }

  // 10. assess_file_health (A1)
  {
    final good = '${dir.path}/good.ppm';
    writeNoisePpm(good, 128, 128, 0x1357);
    final h = lib.assessFileHealth(good);
    check(
      h.minEntropyPerByte > 1.0 && h.rctPassed && h.aptPassed && h.healthy,
      'assess_file_health: noise carrier healthy',
    );
    final flat = '${dir.path}/flat.ppm';
    final body = <int>[
      ...'P6\n64 64\n255\n'.codeUnits,
      ...List.filled(64 * 64 * 3, 0),
    ];
    File(flat).writeAsBytesSync(body);
    check(
      !lib.assessFileHealth(flat).healthy,
      'assess_file_health: constant carrier flagged',
    );
  }

  dir.deleteSync(recursive: true);
  stdout.writeln(_failures == 0 ? 'ALL PASS' : '$_failures FAILURE(S)');
  exit(_failures == 0 ? 0 : 1);
}
