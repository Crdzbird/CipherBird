@TestOn('browser')
library;

import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List hex(String h) => Uint8List.fromList([
  for (var i = 0; i < h.length; i += 2)
    int.parse(h.substring(i, i + 2), radix: 16),
]);
String toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  final fips = DeviceFips.platform();

  test('the module says what it is', () async {
    final info = await fips.module();
    expect(info.module, contains('WebCrypto'));
    expect(info.module, contains('not a validated module'));
    expect(info.providers['aesGcm'], 'WebCrypto');
  });

  test('known answers: SHA-256, HMAC RFC 4231, HKDF RFC 5869, PBKDF2', () async {
    expect(
      toHex(await fips.digest(FipsHash.sha256, ascii('abc'))),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    final key = Uint8List.fromList(List.filled(20, 0x0b));
    expect(
      toHex(await fips.hmac(FipsHash.sha256, key, ascii('Hi There'))),
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    );
    final okm = await fips.hkdf(
      FipsHash.sha256,
      Uint8List.fromList(List.filled(22, 0x0b)),
      salt: hex('000102030405060708090a0b0c'),
      info: hex('f0f1f2f3f4f5f6f7f8f9'),
      count: 42,
    );
    expect(
      toHex(okm),
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
    final dk = await fips.pbkdf2(
      FipsHash.sha256,
      ascii('passwordPASSWORDpassword'),
      ascii('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
      iterations: 4096,
      count: 40,
    );
    expect(
      toHex(dk),
      '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9',
    );
  });

  test('agrees with the engine and interoperates on AES-GCM', () async {
    final msg = ascii('the same bytes on every platform');
    final k = lib.randomBytes(32);
    expect(await fips.digest(FipsHash.sha256, msg), lib.sha256(msg));
    expect(await fips.hmac(FipsHash.sha256, k, msg), lib.hmacSha256(msg, k));
    final aad = ascii('ctx');
    final fromWeb = await fips.aesGcmEncrypt(k, msg, aad: aad);
    expect(lib.aes256gcmDecrypt(fromWeb, k, aad), msg);
    final fromEngine = lib.aes256gcmEncrypt(msg, k, aad);
    expect(await fips.aesGcmDecrypt(k, fromEngine, aad: aad), msg);
    final tampered = Uint8List.fromList(fromWeb)..[20] ^= 1;
    await expectLater(
      fips.aesGcmDecrypt(k, tampered, aad: aad),
      throwsA(isA<FipsException>()),
    );
    expect((await fips.random(70000)).length, 70000);
  });

  test('P-256 ECDH agrees and ECDSA verifies in DER', () async {
    final a = await fips.p256Keygen();
    final b = await fips.p256Keygen();
    expect(a.publicKey, hasLength(65));
    expect(a.secretKey, hasLength(32));
    expect(
      await fips.p256Ecdh(a.secretKey, b.publicKey),
      await fips.p256Ecdh(b.secretKey, a.publicKey),
    );
    final msg = ascii('sign me');
    final sig = await fips.p256Sign(a.secretKey, msg);
    expect(sig[0], 0x30);
    expect(await fips.p256Verify(a.publicKey, msg, sig), isTrue);
    expect(await fips.p256Verify(a.publicKey, ascii('other'), sig), isFalse);
    expect(await fips.p256Verify(b.publicKey, msg, sig), isFalse);
  });
}
