import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

Uint8List hex(String h) => Uint8List.fromList([
  for (var i = 0; i < h.length; i += 2)
    int.parse(h.substring(i, i + 2), radix: 16),
]);
String toHex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List ascii(String s) => Uint8List.fromList(s.codeUnits);

/// Runs on a device, simulator or emulator and exercises the platform's
/// validated module end to end against known answers and the engine:
/// `flutter test integration_test/fips_test.dart -d <device id>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  late DeviceFips fips;

  setUpAll(() async {
    await CipherBird.preload();
    fips = DeviceFips.platform();
    final info = await fips.module();
    debugPrint(
      'cipherbird fips module: ${info.module} on ${info.platform} '
      '${info.providers} hkdfComposed=${info.hkdfComposed} '
      'pbkdf2Composed=${info.pbkdf2Composed}',
    );
  });

  testWidgets('digests, MACs and KDFs match the published vectors', (_) async {
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
    final lib = CipherBird.instance;
    final msg = lib.randomBytes(100);
    final k = lib.randomBytes(32);
    expect(await fips.digest(FipsHash.sha256, msg), lib.sha256(msg));
    expect(await fips.hmac(FipsHash.sha256, k, msg), lib.hmacSha256(msg, k));
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
    final salt = lib.randomBytes(16);
    final a = await fips.pbkdf2(
      FipsHash.sha256,
      ascii('pw'),
      salt,
      iterations: 1000,
    );
    final b = await fips.pbkdf2(
      FipsHash.sha256,
      ascii('pw'),
      salt,
      iterations: 1000,
    );
    expect(a, b);
    expect(a.length, 32);
    expect((await fips.random(16)).length, 16);
  });

  testWidgets('AES-256-GCM round trips and rejects tampering', (_) async {
    final key = await fips.random(32);
    final wire = await fips.aesGcmEncrypt(
      key,
      ascii('cardholder data'),
      aad: ascii('ctx'),
    );
    expect(wire.length, 12 + 15 + 16);
    expect(
      String.fromCharCodes(
        await fips.aesGcmDecrypt(key, wire, aad: ascii('ctx')),
      ),
      'cardholder data',
    );
    final bad = Uint8List.fromList(wire);
    bad[20] ^= 1;
    await expectLater(
      fips.aesGcmDecrypt(key, bad, aad: ascii('ctx')),
      throwsA(isA<FipsException>()),
    );
    await expectLater(
      fips.aesGcmDecrypt(key, wire),
      throwsA(isA<FipsException>()),
    );
  });

  testWidgets('P-256 agrees and signs', (_) async {
    final alice = await fips.p256Keygen();
    final bob = await fips.p256Keygen();
    expect(alice.publicKey.length, 65);
    expect(alice.secretKey.length, 32);
    final s1 = await fips.p256Ecdh(alice.secretKey, bob.publicKey);
    final s2 = await fips.p256Ecdh(bob.secretKey, alice.publicKey);
    expect(s1, s2);
    expect(s1.length, 32);
    final sig = await fips.p256Sign(alice.secretKey, ascii('transaction 42'));
    expect(
      await fips.p256Verify(alice.publicKey, ascii('transaction 42'), sig),
      isTrue,
    );
    expect(
      await fips.p256Verify(alice.publicKey, ascii('transaction 43'), sig),
      isFalse,
    );
    expect(
      await fips.p256Verify(bob.publicKey, ascii('transaction 42'), sig),
      isFalse,
    );
  });
}
