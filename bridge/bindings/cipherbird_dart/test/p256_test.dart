import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  const isWeb = bool.fromEnvironment('dart.library.js_interop');
  var available = false;
  try {
    available = lib.p256Available();
  } on Object {
    available = false;
  }
  if (!available) {
    test('P-256 is not in this engine', () {
      expect(available, isFalse);
    }, skip: 'the loaded engine has no libcrypto EC (mobile and web trims)');
    return;
  }
  Uint8List bytes(String s) => Uint8List.fromList(utf8.encode(s));
  Uint8List unhex(String text) {
    final h = text.length.isOdd ? '0$text' : text;
    return Uint8List.fromList(
      List.generate(
        h.length ~/ 2,
        (i) => int.parse(h.substring(2 * i, 2 * i + 2), radix: 16),
      ),
    );
  }

  Uint8List cat(List<List<int>> parts) =>
      Uint8List.fromList([for (final p in parts) ...p]);
  Uint8List point(String qx, String qy) => cat([
    [4],
    unhex(qx),
    unhex(qy),
  ]);
  const pem =
      '-----BEGIN PRIVATE KEY-----\n'
      'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgY+CswOufc3tZq8lE\n'
      'Po6kGO5zjOLzF/kscuSONqd1FHahRANCAASkcmg2wgIEinXnLanT48k0734kS7Ut\n'
      '5+QWxsgXYKuevjC+TcBfa1F69FCJtY7mWuNQ49vGHtWSoxIREPo4V3fY\n'
      '-----END PRIVATE KEY-----\n';
  final pemSecret = unhex(
    '63e0acc0eb9f737b59abc9443e8ea418ee738ce2f317f92c72e48e36a7751476',
  );
  final order = unhex(
    'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',
  );

  group('P-256 ECDSA with SHA-256', () {
    test('round trip, shapes and refusals', () {
      final k = lib.p256GenerateKey();
      expect(k.secretKey.length, 32);
      expect(k.publicKey.length, 65);
      expect(k.publicKey.first, 4);
      expect(lib.p256PublicKey(k.secretKey), k.publicKey);
      for (final m in [Uint8List(0), bytes('m'), Uint8List(100000)]) {
        final s = lib.p256Sign(k.secretKey, m);
        expect(s.length, 64);
        expect(lib.p256Verify(k.publicKey, m, s), isTrue);
        expect(lib.p256Verify(k.publicKey, bytes('other'), s), isFalse);
        expect(lib.p256Verify(k.publicKey, m, s.sublist(0, 63)), isFalse);
        expect(lib.p256Verify(k.publicKey.sublist(1), m, s), isFalse);
        expect(lib.p256Verify(Uint8List(0), m, s), isFalse);
        final other = lib.p256GenerateKey();
        expect(lib.p256Verify(other.publicKey, m, s), isFalse);
      }
      expect(() => lib.p256Sign(Uint8List(32), bytes('m')), throwsException);
      expect(() => lib.p256Sign(order, bytes('m')), throwsException);
      expect(() => lib.p256PublicKey(Uint8List(31)), throwsException);
      expect(() => lib.p256PublicKey(Uint8List(0)), throwsException);
    });

    test('PKCS#8 import of a key OpenSSL wrote, and its strictness', () {
      final k = lib.p256PrivateKeyFromPem(pem);
      expect(k.secretKey, pemSecret);
      expect(lib.p256PublicKey(k.secretKey), k.publicKey);
      final der = base64.decode(pem.split('\n').sublist(1, 4).join());
      final fromDer = lib.p256PrivateKeyFromPkcs8(der);
      expect(fromDer.secretKey, pemSecret);
      expect(fromDer.publicKey, k.publicKey);
      final s = lib.p256Sign(k.secretKey, bytes('header.claims'));
      expect(lib.p256Verify(k.publicKey, bytes('header.claims'), s), isTrue);
      Matcher refuses(String why) => throwsA(
        isA<Exception>().having((e) => '$e', 'message', contains(why)),
      );
      expect(
        () => lib.p256PrivateKeyFromPkcs8(
          cat([
            der,
            [0],
          ]),
        ),
        refuses('PrivateKeyInfo'),
      );
      expect(
        () => lib.p256PrivateKeyFromPkcs8(der.sublist(0, 100)),
        refuses('p256:'),
      );
      final flipped = Uint8List.fromList(der)..[40] ^= 1;
      expect(() => lib.p256PrivateKeyFromPkcs8(flipped), refuses('p256:'));
      expect(
        () => lib.p256PrivateKeyFromPem(
          pem.replaceAll('PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'),
        ),
        refuses('encrypted'),
      );
      expect(
        () => lib.p256PrivateKeyFromPem(
          pem.replaceAll('PRIVATE KEY', 'EC PRIVATE KEY'),
        ),
        refuses('SEC 1'),
      );
      expect(
        () => lib.p256PrivateKeyFromPem('junk\n$pem'),
        refuses('PRIVATE KEY block'),
      );
      expect(() => lib.p256PrivateKeyFromPem(''), refuses('size'));
    });

    test('the shared vectors: RFC 6979 A.2.5 and NIST CAVP', () {
      if (isWeb) {
        return;
      }
      final v =
          jsonDecode(
                File(
                  '../../../tests/vectors/p256/ecdsa_p256_sha256.json',
                ).readAsStringSync(),
              )
              as Map<String, Object?>;
      List<Map<String, Object?>> rows(String name) =>
          (v[name]! as List).cast<Map<String, Object?>>();
      String f(Map<String, Object?> t, String name) => t[name]! as String;
      final rfc = v['rfc6979']! as Map<String, Object?>;
      final d = unhex(f(rfc, 'd'));
      final q = point(f(rfc, 'qx'), f(rfc, 'qy'));
      expect(lib.p256PublicKey(d), q);
      final cases = (rfc['cases']! as List).cast<Map<String, Object?>>();
      expect(cases.length, 2);
      for (final t in cases) {
        final want = cat([unhex(f(t, 'r')), unhex(f(t, 's'))]);
        final m = bytes(f(t, 'message'));
        expect(lib.p256Verify(q, m, want), isTrue);
        if (lib.p256DeterministicNonces()) {
          expect(lib.p256Sign(d, m), want, reason: f(t, 'message'));
        }
      }
      for (final t in rows('keypair')) {
        expect(
          lib.p256PublicKey(unhex(f(t, 'd'))),
          point(f(t, 'qx'), f(t, 'qy')),
        );
      }
      expect(rows('sigver').length, 15);
      for (final t in rows('sigver')) {
        expect(
          lib.p256Verify(
            point(f(t, 'qx'), f(t, 'qy')),
            unhex(f(t, 'message')),
            cat([unhex(f(t, 'r')), unhex(f(t, 's'))]),
          ),
          t['valid'],
          reason: f(t, 'note'),
        );
      }
      for (final t in rows('siggen')) {
        final key = unhex(f(t, 'd'));
        final pub = point(f(t, 'qx'), f(t, 'qy'));
        final m = unhex(f(t, 'message'));
        final recorded = cat([unhex(f(t, 'r')), unhex(f(t, 's'))]);
        expect(lib.p256Verify(pub, m, recorded), isTrue);
        expect(lib.p256Verify(pub, m, lib.p256Sign(key, m)), isTrue);
      }
      final sample = cases.first;
      final r = unhex(f(sample, 'r'));
      final s = unhex(f(sample, 's'));
      final m = bytes(f(sample, 'message'));
      for (final bad in [
        cat([Uint8List(32), s]),
        cat([r, Uint8List(32)]),
        cat([order, s]),
        cat([r, order]),
      ]) {
        expect(lib.p256Verify(q, m, bad), isFalse);
      }
      final off = Uint8List.fromList(q)..[64] ^= 1;
      expect(lib.p256Verify(off, m, cat([r, s])), isFalse);
    });
  });
}
