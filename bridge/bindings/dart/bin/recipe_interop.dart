// Cross-language Recipe interop: seal a fixed set of configurations to a
// directory, or open and verify them.
//   dart run bin/recipe_interop.dart seal|open <dir> <dylib>
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

// Fixed inputs so every language derives identical keys.
const keyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
const skHex = 'd463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6';
const passphrase = 'interop passphrase';
const plaintext = 'cross-language recipe envelope';

Uint8List hx(String s) {
  final o = Uint8List(s.length ~/ 2);
  for (var i = 0; i < o.length; i++) {
    o[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return o;
}

List<(String, CryptoRecipe)> configs(CryptoLib lib, Uint8List pk, Uint8List sk) => [
      ('balanced', lib.recipe().withKey(hx(keyHex))),
      ('maximum', lib.recipe(SecurityProfile.maximum).withKey(hx(keyHex))),
      ('signed', lib.recipe(SecurityProfile.high).withKey(hx(keyHex))
          .signedBy(sk).verifiedBy(pk)),
      ('passphrase', lib.recipe().withPassphrase(passphrase)
          .argon2Cost(ops: 1, memoryBytes: 8 * 1024 * 1024)),
      ('fec', lib.recipe().withKey(hx(keyHex)).withFec(FecScheme.repetition3)),
    ];

void main(List<String> args) {
  final mode = args[0], dir = args[1];
  final lib = CryptoLib.load(args.length > 2 ? args[2] : 'build/release/libcryptolib_c.dylib');
  lib.init();
  final kp = lib.ed25519KeygenFromSeed(hx(skHex));
  final pk = kp.publicKey, sk = kp.secretKey;
  final pt = Uint8List.fromList(plaintext.codeUnits);
  var failures = 0;

  for (final (name, recipe) in configs(lib, pk, sk)) {
    final f = File('$dir/$name.bin');
    if (mode == 'seal') {
      f.writeAsBytesSync(recipe.seal(pt));
    } else {
      try {
        final got = recipe.open(f.readAsBytesSync());
        final ok = String.fromCharCodes(got) == plaintext;
        stdout.writeln('${ok ? "  ok  " : " FAIL "} dart opens $name');
        if (!ok) failures++;
      } catch (e) {
        stdout.writeln(' FAIL  dart opens $name: $e');
        failures++;
      }
    }
  }
  if (mode == 'seal') stdout.writeln('  dart sealed ${configs(lib, pk, sk).length} envelopes');
  exit(failures == 0 ? 0 : 1);
}
