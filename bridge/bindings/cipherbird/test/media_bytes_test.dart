import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List photoPpm(int size, int seed) {
  final head = 'P6\n$size $size\n255\n'.codeUnits;
  final body = Uint8List(size * size * 3);
  var s = seed | 1;
  for (var i = 0; i < body.length; i++) {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    body[i] = (128 + (i % 64) + (s % 24) - 12).clamp(0, 255);
  }
  return Uint8List.fromList([...head, ...body]);
}

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  final cover = photoPpm(128, 3);
  final keyPhoto = photoPpm(64, 99);
  final secret = Uint8List.fromList('the eagle lands at dawn'.codeUnits);
  const ppm = MediaFormat.ppmImage;

  group('steganography on bytes', () {
    test('plain, keyed and encrypted round trips', () {
      expect(lib.stegoCapacityOf(cover, ppm), greaterThan(secret.length));
      final hidden = lib.stegoEmbedBytes(cover, ppm, secret);
      expect(hidden.length, cover.length);
      expect(lib.stegoExtractBytes(hidden, ppm), secret);
      final key = lib.randomBytes(32);
      final keyed = lib.stegoEmbedKeyedBytes(cover, ppm, secret, key);
      expect(lib.stegoExtractKeyedBytes(keyed, ppm, key), secret);
      expect(
        () => lib.stegoExtractKeyedBytes(keyed, ppm, lib.randomBytes(32)),
        throwsException,
      );
      final sealed = lib.stegoEmbedEncryptedBytes(cover, ppm, secret, key);
      expect(lib.stegoExtractDecryptBytes(sealed, ppm, key), secret);
      expect(lib.stegoDetectHiddenBytes(hidden, ppm).cipherbirdPayload, isTrue);
      expect(
        lib.stegoDetectHiddenBytes(sealed, ppm).cipherbirdPayload,
        isFalse,
      );
    });

    test('inspect and digest see the decoded content', () {
      final r = lib.stegoInspectBytes(cover, ppm);
      expect(r.parses, isTrue);
      expect(r.format, ppm);
      expect(r.width, 128);
      expect(lib.stegoContentDigestOf(cover, ppm), hasLength(32));
      expect(
        lib.stegoContentDigestOf(cover, ppm),
        lib.stegoContentDigestOf(cover, ppm),
      );
    });
  });

  group('composed seals on bytes', () {
    test('physical, hpke and image factor', () {
      final aad = Uint8List.fromList('ctx'.codeUnits);
      final physical = lib.physicalSealBytes(
        keyMedia: keyPhoto,
        keyMediaFormat: ppm,
        plaintext: secret,
        cover: cover,
        coverFormat: ppm,
        aad: aad,
      );
      expect(
        lib.physicalOpenBytes(
          keyMedia: keyPhoto,
          keyMediaFormat: ppm,
          stego: physical,
          stegoFormat: ppm,
          aad: aad,
        ),
        secret,
      );
      final bob = lib.hpkeKeygen();
      final sealed = lib.hpkeStegoSealBytes(
        recipientPublic: bob.publicKey,
        plaintext: secret,
        cover: cover,
        coverFormat: ppm,
      );
      expect(
        lib.hpkeStegoOpenBytes(
          recipientSecret: bob.secretKey,
          enc: sealed.enc,
          stego: sealed.carrier,
          stegoFormat: ppm,
        ),
        secret,
      );
      final seed = lib.randomBytes(32);
      final factor = lib.imageFactorSealBytes(
        oprfSecretSeed: seed,
        referenceImage: keyPhoto,
        referenceFormat: ppm,
        plaintext: secret,
        cover: cover,
        coverFormat: ppm,
      );
      expect(
        lib.imageFactorOpenBytes(
          oprfSecretSeed: seed,
          referenceImage: keyPhoto,
          referenceFormat: ppm,
          stego: factor,
          stegoFormat: ppm,
        ),
        secret,
      );
    });
  });

  group('media entropy on bytes', () {
    test('policy, keys, seals and the recipe source', () {
      final h = lib.assessHealthOf(cover);
      expect(h.minEntropyPerByte, greaterThan(1.0));
      expect(
        () => lib.entropyFromBytes(Uint8List(4096)),
        throwsA(predicate((e) => '$e'.contains('policy floor'))),
      );
      final handle = lib.entropyFromBytes(cover, deterministic: true);
      expect(lib.entropyInfo(handle).entropyBits, greaterThan(0));
      lib.entropyFree(handle);
      expect(lib.keyFromBytes(cover), hasLength(32));
      final packet = lib.sealWithBytes(cover, 'hello', 'aad');
      expect(
        String.fromCharCodes(lib.openWithBytes(cover, packet, 'aad')),
        'hello',
      );
      expect(() => lib.openWithBytes(keyPhoto, packet, 'aad'), throwsException);
      final recipe = lib.recipe().withKeySource(KeyBytesSource(cover));
      final env = recipe.seal(secret);
      expect(
        lib.recipe().withKeySource(KeyBytesSource(cover)).open(env),
        secret,
      );
      expect(
        () => lib.recipe().withKeySource(KeyBytesSource(keyPhoto)).open(env),
        throwsException,
      );
    });
  });
}
