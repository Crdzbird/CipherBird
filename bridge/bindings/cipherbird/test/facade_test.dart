// Exercises the additions: the grouped namespaces, the algorithm enums, and the
// features that previously had no Dart binding at all.
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

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
  final lib = CryptoLib.instance;
  late Directory dir;

  setUpAll(() => dir = Directory.systemTemp.createTempSync('cl_facade_'));
  tearDownAll(() => dir.deleteSync(recursive: true));

  group('grouped namespaces', () {
    test('hash + aead reachable through their groups', () {
      final digest = lib.hash.sha256(Uint8List.fromList('abc'.codeUnits));
      expect(
        digest,
        lib.sha256(Uint8List.fromList('abc'.codeUnits)),
        reason: 'grouped and flat calls must hit the same native function',
      );

      final key = lib.aead.symKeygen();
      final pt = Uint8List.fromList('grouped api'.codeUnits);
      expect(
        lib.aead.xchacha20Decrypt(lib.aead.xchacha20Encrypt(pt, key), key),
        pt,
      );
    });

    test('pq sub-namespaces round-trip with enum levels', () {
      final kp = lib.pq.mlKem.keygen(MlKemLevel.level768);
      final (ct, ss) = lib.pq.mlKem.encapsulate(
        kp.publicKey,
        MlKemLevel.level768,
      );
      expect(
        lib.pq.mlKem.decapsulate(ct, kp.secretKey, MlKemLevel.level768),
        ss,
      );

      final sk = lib.pq.mlDsa.keygen(MlDsaLevel.level65);
      final msg = Uint8List.fromList('sign me'.codeUnits);
      final sig = lib.pq.mlDsa.sign(msg, sk.secretKey, MlDsaLevel.level65);
      expect(
        lib.pq.mlDsa.verify(msg, sig, sk.publicKey, MlDsaLevel.level65),
        isTrue,
      );
    });

    test('enums carry their wire encoding and metadata', () {
      expect(MlKemLevel.level768.value, 1);
      expect(MlKemLevel.level768.bits, 768);
      expect(MlKemLevel.level768.nistCategory, 3);
      expect(SlhDsaLevel.fast192.fastVariant, isTrue);
      expect(SlhDsaLevel.small192.fastVariant, isFalse);
      expect(
        HpkeMode.authPsk.requiresPsk && HpkeMode.authPsk.requiresSenderKey,
        isTrue,
      );
      expect(HpkeMode.base.requiresPsk, isFalse);
      expect(SealedTier.fromSuiteId(2), SealedTier.fortress);
    });
  });

  group('previously unbound features', () {
    test('HMAC-DRBG is deterministic for a given seed and reseeds', () {
      final entropy = Uint8List.fromList(List.filled(48, 7));
      final a = lib.rng.drbg(
        entropy,
        personalization: Uint8List.fromList('ctx'.codeUnits),
      );
      final b = lib.rng.drbg(
        entropy,
        personalization: Uint8List.fromList('ctx'.codeUnits),
      );
      try {
        expect(
          a.generate(32),
          b.generate(32),
          reason: 'same seed -> same stream',
        );
        a.reseed(Uint8List.fromList(List.filled(48, 9)));
        expect(a.generate(32), isNot(b.generate(32)));
      } finally {
        a.close();
        b.close();
        a.close(); // idempotent
      }
    });

    test('rng.bytes draws distinct values from the OS CSPRNG', () {
      final a = lib.rng.bytes(32);
      expect(a.length, 32);
      expect(a, isNot(lib.rng.bytes(32)));
    });

    test('Fortuna refuses to generate until seeded, then heals', () {
      final f = lib.rng.fortuna();
      try {
        expect(f.reseedCount(), 0);
        expect(() => f.generate(16), throwsA(anything));
        for (var src = 0; src < 4; src++) {
          f.addEntropy(src, Uint8List.fromList(List.filled(32, src + 1)));
        }
        f.reseed();
        expect(f.reseedCount(), greaterThan(0));
        expect(f.generate(32).length, 32);
      } finally {
        f.close();
      }
    });

    test('FEC survives a corrupted bit', () {
      final data = Uint8List.fromList('correct me'.codeUnits);
      final encoded = lib.composed.fecEncode(data, FecScheme.repetition3);
      expect(encoded.length, greaterThan(data.length));
      encoded[0] ^= 1; // single-bit error inside a triple
      expect(
        lib.composed.fecDecode(encoded, FecScheme.repetition3, data.length),
        data,
      );
    });

    test('carrier inspection reports true format and detects a payload', () {
      final cover = '${dir.path}/cover.ppm';
      final out = '${dir.path}/stego.ppm';
      File(cover).writeAsBytesSync(_noisePpm(128, 128, 0xC0FFEE));

      final info = lib.stego.inspect(cover);
      expect(info.parses, isTrue);
      expect(info.format, MediaFormat.ppmImage);
      expect(info.extensionMatches, isTrue);
      expect(info.width, 128);
      expect(info.height, 128);

      // Unkeyed payload is discoverable; the keyed one is not trivially so.
      lib.stegoEmbed(cover, Uint8List.fromList('plain'.codeUnits), out);
      expect(lib.stego.detectHidden(out).cryptolibPayload, isTrue);
    });

    test('keyed and encrypted stego round-trip; wrong key fails closed', () {
      final cover = '${dir.path}/c2.ppm';
      final k1 = '${dir.path}/k1.ppm';
      final e1 = '${dir.path}/e1.ppm';
      File(cover).writeAsBytesSync(_noisePpm(128, 128, 0xBEEF));
      final key = Uint8List.fromList(List.filled(32, 0x5a));
      final wrong = Uint8List.fromList(List.filled(32, 0x99));
      final payload = Uint8List.fromList('keyed payload'.codeUnits);

      lib.stego.embedKeyed(cover, payload, k1, key);
      expect(lib.stego.extractKeyed(k1, key), payload);
      expect(() => lib.stego.extractKeyed(k1, wrong), throwsA(anything));

      lib.stego.embedEncrypted(cover, payload, e1, key);
      expect(lib.stego.extractDecrypt(e1, key), payload);
      expect(() => lib.stego.extractDecrypt(e1, wrong), throwsA(anything));
    });

    test('content digest ignores the container, tracks the samples', () {
      final a = '${dir.path}/d1.ppm';
      final b = '${dir.path}/d2.ppm';
      final bytes = _noisePpm(64, 64, 0x1234);
      File(a).writeAsBytesSync(bytes);
      File(b).writeAsBytesSync(bytes);
      expect(lib.stego.contentDigest(a), lib.stego.contentDigest(b));
    });

    test('entropy health separates a noisy source from a flat one', () {
      final noisy = '${dir.path}/noisy.ppm';
      final flat = '${dir.path}/flat.ppm';
      File(noisy).writeAsBytesSync(_noisePpm(128, 128, 0xABCD));
      File(flat).writeAsBytesSync(
        Uint8List.fromList([
          ...'P6\n128 128\n255\n'.codeUnits,
          ...List.filled(128 * 128 * 3, 0),
        ]),
      );

      final good = lib.entropy.assessFileHealth(noisy);
      final bad = lib.entropy.assessFileHealth(flat);
      expect(good.minEntropyPerByte, greaterThan(bad.minEntropyPerByte));
      expect(
        bad.healthy,
        isFalse,
        reason: 'an all-zero file must fail the health tests',
      );
    });

    test('physical seal needs both the key media and the carrier', () {
      final keyMedia = '${dir.path}/key.ppm';
      final cover = '${dir.path}/pcover.ppm';
      final out = '${dir.path}/psealed.ppm';
      final decoy = '${dir.path}/decoy.ppm';
      File(keyMedia).writeAsBytesSync(_noisePpm(96, 96, 0x5EED));
      File(cover).writeAsBytesSync(_noisePpm(160, 160, 0x0FF1CE));
      File(decoy).writeAsBytesSync(_noisePpm(96, 96, 0xDEC0DE));

      final secret = Uint8List.fromList('two files required'.codeUnits);
      lib.composed.physicalSeal(
        keyMediaPath: keyMedia,
        plaintext: secret,
        coverPath: cover,
        outputPath: out,
      );
      expect(
        lib.composed.physicalOpen(keyMediaPath: keyMedia, stegoPath: out),
        secret,
      );
      expect(
        () => lib.composed.physicalOpen(keyMediaPath: decoy, stegoPath: out),
        throwsA(anything),
        reason: 'a different key file must not open it',
      );
    });
  });
}
