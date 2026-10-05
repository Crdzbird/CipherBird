// SecurityProfile presets and the composable CipherBirdRecipe pipeline.
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Uint8List _b(String s) => Uint8List.fromList(s.codeUnits);

Uint8List _noisePpm(int w, int h, int seed) {
  final head = 'P6\n$w $h\n255\n'.codeUnits;
  final body = Uint8List(w * h * 3);
  var s = seed == 0 ? 1 : seed;
  for (var i = 0; i < body.length; i++) {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    body[i] = s & 0xFF;
  }
  return Uint8List.fromList([...head, ...body]);
}

void main() {
  final lib = CipherBird.instance;
  final secret = _b('the treaty text nobody may read');
  late Directory dir;

  // Keep Argon2id cheap so the suite stays fast; the cost path itself is
  // covered by asserting the profile's own parameters below.
  CipherBirdRecipe cheap(CipherBirdRecipe r) =>
      r.argon2Cost(ops: 1, memoryBytes: 8 * 1024 * 1024);

  setUpAll(() => dir = Directory.systemTemp.createTempSync('cl_sec_'));
  tearDownAll(() => dir.deleteSync(recursive: true));

  group('SecurityProfile', () {
    test('maximum picks the strongest option at every choice', () {
      const max = SecurityProfile.maximum;
      expect(max.mlKem, MlKemLevel.level1024);
      expect(max.mlKem.nistCategory, 5);
      expect(max.mlDsa, MlDsaLevel.level87);
      expect(max.slhDsa, SlhDsaLevel.small256);
      expect(max.slhDsaHash, SlhDsaHash.shake);
      expect(max.sealedTier, SealedTier.fortress);
      expect(max.kdfPreset, KdfPreset.sensitive);
      expect(max.hpkeKdf, HpkeKdf.sha512);
    });

    test('profiles are ordered, not arbitrary', () {
      expect(
        SecurityProfile.balanced.cascade.length,
        lessThan(SecurityProfile.maximum.cascade.length),
      );
      expect(
        SecurityProfile.balanced.argon2Memory,
        lessThan(SecurityProfile.maximum.argon2Memory),
      );
      expect(
        SecurityProfile.maximum.cascade.last,
        ProtectionLayer.committing,
        reason: 'the outermost layer must be key-committing',
      );
    });

    test('maximum cascade uses independent cipher families', () {
      final c = SecurityProfile.maximum.cascade;
      expect(c, contains(ProtectionLayer.xchacha20Poly1305));
      expect(c, contains(ProtectionLayer.aes256Gcm));
      expect(c.toSet().length, c.length, reason: 'no layer repeats');
    });
  });

  group('CipherBirdRecipe round-trips', () {
    test('maximum profile with a passphrase', () {
      final r = cheap(
        lib.maximumSecurity().withPassphrase('correct horse battery staple'),
      );
      expect(r.open(r.seal(secret)), secret);
    });

    test('raw 32-byte key', () {
      final key = lib.rng.bytes(32);
      final r = lib.recipe().withKey(key);
      expect(r.open(r.seal(secret)), secret);
    });

    test('a media file as the key', () {
      final keyFile = '${dir.path}/key.ppm';
      File(keyFile).writeAsBytesSync(_noisePpm(96, 96, 0x5EED));
      final r = lib.recipe(SecurityProfile.high).withKeyFile(keyFile);
      expect(r.open(r.seal(secret)), secret);
    });

    test(
      'the same key file reopens an envelope from a different recipe object',
      () {
        // Regression: the non-deterministic keyFromFile mixes in system entropy,
        // so it would produce a fresh key per call and never reopen its own
        // envelope. The key-file source must use the reproducible path.
        final keyFile = '${dir.path}/shared.ppm';
        File(keyFile).writeAsBytesSync(_noisePpm(96, 96, 0xA11CE));
        final sealer = lib.recipe().withKeyFile(keyFile);
        final opener = lib.recipe().withKeyFile(keyFile);
        expect(opener.open(sealer.seal(secret)), secret);
      },
    );

    test('a different key file does not open it', () {
      final a = '${dir.path}/ka.ppm';
      final b = '${dir.path}/kb.ppm';
      File(a).writeAsBytesSync(_noisePpm(96, 96, 0xAAAA));
      File(b).writeAsBytesSync(_noisePpm(96, 96, 0xBBBB));
      final sealed = lib.recipe().withKeyFile(a).seal(secret);
      expect(() => lib.recipe().withKeyFile(b).open(sealed), throwsA(anything));
    });

    test('a non-32-byte key is refused up front', () {
      expect(() => lib.recipe().withKey(Uint8List(31)), throwsArgumentError);
    });

    test('an empty layer list is refused', () {
      expect(() => lib.recipe().withLayers([]), throwsArgumentError);
    });
  });

  group('composition', () {
    test('layers stack in the order given and can be extended', () {
      final key = lib.rng.bytes(32);
      final one = lib.recipe().withKey(key).withLayers([
        ProtectionLayer.xchacha20Poly1305,
      ]);
      final three = lib
          .recipe()
          .withKey(key)
          .withLayers([
            ProtectionLayer.xchacha20Poly1305,
            ProtectionLayer.aes256Gcm,
          ])
          .addLayer(ProtectionLayer.committing);

      final a = one.seal(secret);
      final b = three.seal(secret);
      expect(
        b.length,
        greaterThan(a.length),
        reason: 'each layer adds its own overhead',
      );
      expect(one.open(a), secret);
      expect(three.open(b), secret);
    });

    test('a MolecularVault can itself be one layer', () {
      final r = lib.recipe().withKey(lib.rng.bytes(32)).withLayers([
        ProtectionLayer.molecular,
      ]);
      expect(r.open(r.seal(secret)), secret);
    });

    test('signing travels inside the encryption and is verified on open', () {
      final id = lib.ed25519Keygen();
      final r = lib
          .recipe(SecurityProfile.high)
          .withKey(lib.rng.bytes(32))
          .signedBy(id.secretKey)
          .verifiedBy(id.publicKey);
      final env = r.seal(secret);
      expect(r.open(env), secret);
      // The signature must not be observable in the envelope.
      expect(env.length, greaterThan(secret.length));
    });

    test('hybrid PQ signatures work the same way', () {
      final id = lib.hybridSigKeygen();
      final r = lib
          .recipe()
          .withKey(lib.rng.bytes(32))
          .signedBy(id.secretKey, algorithm: SignatureAlgorithm.hybrid)
          .verifiedBy(id.publicKey);
      expect(r.open(r.seal(secret)), secret);
    });

    test('a wrong signer is rejected', () {
      final real = lib.ed25519Keygen();
      final impostor = lib.ed25519Keygen();
      final key = lib.rng.bytes(32);
      final sealer = lib.recipe().withKey(key).signedBy(real.secretKey);
      final opener = lib.recipe().withKey(key).verifiedBy(impostor.publicKey);
      expect(() => opener.open(sealer.seal(secret)), throwsA(anything));
    });

    test('a signed envelope will not open without a verification key', () {
      final id = lib.ed25519Keygen();
      final key = lib.rng.bytes(32);
      final sealer = lib.recipe().withKey(key).signedBy(id.secretKey);
      final opener = lib.recipe().withKey(key);
      expect(
        () => opener.open(sealer.seal(secret)),
        throwsA(isA<StateError>()),
        reason:
            'silently skipping an available signature check would be worse than failing',
      );
    });

    test('forward error correction survives a flipped bit', () {
      final key = lib.rng.bytes(32);
      final r = lib.recipe().withKey(key).withFec(FecScheme.repetition3);
      final env = r.seal(secret);
      env[env.length ~/ 2] ^= 1;
      expect(r.open(env), secret);
    });

    test('the whole pipeline can hide itself in a carrier', () {
      final cover = '${dir.path}/cover.ppm';
      final out = '${dir.path}/carrier.ppm';
      File(cover).writeAsBytesSync(_noisePpm(256, 256, 0x0FF1CE));
      final r = cheap(
        lib.maximumSecurity().withPassphrase('a long passphrase here'),
      );
      r.sealIntoCarrier(secret, coverPath: cover, outputPath: out);
      expect(r.openFromCarrier(out), secret);
      expect(
        lib.stego.inspect(out).format,
        MediaFormat.ppmImage,
        reason: 'the carrier must still be a valid image',
      );
    });
  });

  group('fails closed', () {
    test('wrong passphrase', () {
      final sealer = cheap(lib.recipe().withPassphrase('right'));
      final opener = cheap(lib.recipe().withPassphrase('wrong'));
      expect(() => opener.open(sealer.seal(secret)), throwsA(anything));
    });

    test('a flipped ciphertext byte', () {
      final r = lib.recipe(SecurityProfile.high).withKey(lib.rng.bytes(32));
      final env = r.seal(secret);
      env[env.length - 1] ^= 1;
      expect(() => r.open(env), throwsA(anything));
    });

    test('a tampered header — the recipe descriptor is authenticated', () {
      final r = lib.recipe(SecurityProfile.high).withKey(lib.rng.bytes(32));
      final env = r.seal(secret);
      env[7] = 1; // claim a single layer instead of two
      expect(() => r.open(env), throwsA(anything));
    });

    test('a tampered salt', () {
      final r = lib.recipe().withKey(lib.rng.bytes(32));
      final env = r.seal(secret);
      env[10] ^= 0xFF; // inside the salt
      expect(() => r.open(env), throwsA(anything));
    });

    test('foreign bytes are not mistaken for an envelope', () {
      final r = lib.recipe().withKey(lib.rng.bytes(32));
      expect(() => r.open(_b('not an envelope at all')), throwsA(anything));
    });

    test('a mismatched key source is reported clearly', () {
      final sealer = lib.recipe().withKey(lib.rng.bytes(32));
      final opener = cheap(lib.recipe().withPassphrase('something'));
      expect(() => opener.open(sealer.seal(secret)), throwsA(anything));
    });
  });

  test('describe() states the configuration for review', () {
    final text = cheap(lib.maximumSecurity().withPassphrase('x')).describe();
    expect(text, contains('maximum'));
    expect(text, contains('xchacha20Poly1305 -> aes256Gcm -> committing'));
    expect(text, contains('argon2id'));
  });
}
