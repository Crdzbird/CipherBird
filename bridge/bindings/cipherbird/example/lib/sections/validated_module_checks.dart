import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// The approved operations through the platform's validated module, each
/// against a published known answer where one exists.
final class ValidatedModuleChecks {
  const ValidatedModuleChecks._();

  static List<Check> build(CipherBird lib) {
    final fips = DeviceFips.platform();
    Check kat(String label, Future<String> Function() body) =>
        Check(label, () async {
          try {
            return await body();
          } on FipsException catch (e) {
            throw SkipCheck('${e.code}: ${e.message}');
          }
        });
    return [
      kat('Module', () async {
        final i = await fips.module();
        return '${i.module} on ${i.platform}${i.hkdfComposed ? ' (HKDF, PBKDF2 loops in app)' : ''}';
      }),
      kat('SHA-256 known answer', () async {
        final h = hexOf(await fips.digest(FipsHash.sha256, ascii('abc')));
        demand(h.startsWith('ba7816bf'), h);
        return h;
      }),
      kat('HMAC-SHA256 RFC 4231 case 1', () async {
        final key = Uint8List.fromList(List.filled(20, 0x0b));
        final t = hexOf(
          await fips.hmac(FipsHash.sha256, key, ascii('Hi There')),
        );
        demand(t.startsWith('b0344c61'), t);
        return t;
      }),
      kat('HKDF-SHA256 RFC 5869 case 1', () async {
        final okm = await fips.hkdf(
          FipsHash.sha256,
          Uint8List.fromList(List.filled(22, 0x0b)),
          salt: bytesOfHex('000102030405060708090a0b0c'),
          info: bytesOfHex('f0f1f2f3f4f5f6f7f8f9'),
          count: 42,
        );
        demand(hexOf(okm).startsWith('3cb25f25'), hexOf(okm));
        return hexOf(okm).substring(0, 32);
      }),
      kat('PBKDF2-HMAC-SHA256 known answer', () async {
        final dk = await fips.pbkdf2(
          FipsHash.sha256,
          ascii('passwordPASSWORDpassword'),
          ascii('saltSALTsaltSALTsaltSALTsaltSALTsalt'),
          iterations: 4096,
          count: 40,
        );
        demand(hexOf(dk).startsWith('348c89db'), hexOf(dk));
        return '4096 iterations, 40 bytes';
      }),
      kat('AES-256-GCM with a module-built nonce', () async {
        final key = await fips.random(32);
        final wire = await fips.aesGcmEncrypt(
          key,
          ascii('cardholder data'),
          aad: ascii('ctx'),
        );
        final pt = await fips.aesGcmDecrypt(key, wire, aad: ascii('ctx'));
        demand(same(pt, ascii('cardholder data')), 'mismatch');
        return 'nonce(12) | ct | tag(16): ${wire.length} bytes';
      }),
      kat('P-256 ECDH and ECDSA', () async {
        final a = await fips.p256Keygen();
        final b = await fips.p256Keygen();
        final s1 = await fips.p256Ecdh(a.secretKey, b.publicKey);
        final s2 = await fips.p256Ecdh(b.secretKey, a.publicKey);
        demand(same(s1, s2), 'ECDH');
        final sig = await fips.p256Sign(a.secretKey, ascii('transaction 42'));
        demand(
          await fips.p256Verify(a.publicKey, ascii('transaction 42'), sig),
          'verify',
        );
        return 'shared secret agrees, ${sig.length}-byte DER signature verifies';
      }),
    ];
  }
}
