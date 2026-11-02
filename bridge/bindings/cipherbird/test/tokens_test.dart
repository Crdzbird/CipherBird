import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  const isWeb = bool.fromEnvironment('dart.library.js_interop');
  Uint8List bytes(String s) => Uint8List.fromList(utf8.encode(s));
  Uint8List counting(int n, int start) =>
      Uint8List.fromList(List.generate(n, (i) => (start + i) & 0xff));
  final key = counting(32, 0x70);
  final other = counting(32, 0x90);
  Matcher invalid() => throwsA(
    isA<TokenException>().having(
      (e) => e.status,
      'status',
      TokenStatus.invalid,
    ),
  );
  Matcher argument() => throwsA(
    isA<TokenException>().having(
      (e) => e.status,
      'status',
      TokenStatus.argument,
    ),
  );

  group('PASETO v4.local', () {
    test('round trips with footer and implicit assertion', () {
      final m = bytes('{"data":"x"}');
      final tok = lib.pasetoV4LocalEncrypt(
        key,
        m,
        footer: bytes('{"kid":"a"}'),
        implicit: bytes('ctx'),
      );
      expect(tok, startsWith('v4.local.'));
      expect('.'.allMatches(tok).length, 3);
      expect(
        lib.pasetoV4LocalDecrypt(
          tok,
          key,
          expectedFooter: bytes('{"kid":"a"}'),
          implicit: bytes('ctx'),
        ),
        m,
      );
      expect(
        () => lib.pasetoV4LocalDecrypt(
          tok,
          other,
          expectedFooter: bytes('{"kid":"a"}'),
          implicit: bytes('ctx'),
        ),
        invalid(),
      );
      expect(
        () => lib.pasetoV4LocalDecrypt(tok, key, implicit: bytes('ctx')),
        invalid(),
      );
      expect(
        () => lib.pasetoV4LocalDecrypt(
          '$tok=',
          key,
          expectedFooter: bytes('{"kid":"a"}'),
          implicit: bytes('ctx'),
        ),
        invalid(),
      );
      expect(() => lib.pasetoV4LocalEncrypt(counting(31, 0), m), argument());
      expect(
        lib.pasetoV4LocalEncrypt(key, m),
        isNot(lib.pasetoV4LocalEncrypt(key, m)),
      );
    });

    test(
      'the official vectors decrypt and the failure vectors are rejected',
      () {
        if (isWeb) {
          return;
        }
        final file = File('../../../tests/vectors/paseto/v4.json');
        final tests =
            (jsonDecode(file.readAsStringSync()) as Map)['tests'] as List;
        var decrypted = 0, rejected = 0;
        for (final t in tests.cast<Map>()) {
          final name = t['name'] as String;
          if (name == '4-F-1' || !RegExp(r'^4-[EF]-').hasMatch(name)) {
            continue;
          }
          final k = Uint8List.fromList(
            List.generate(
              32,
              (i) => int.parse(
                (t['key'] as String).substring(2 * i, 2 * i + 2),
                radix: 16,
              ),
            ),
          );
          final footer = (t['footer'] as String).isEmpty
              ? null
              : bytes(t['footer'] as String);
          final implicit = (t['implicit-assertion'] as String).isEmpty
              ? null
              : bytes(t['implicit-assertion'] as String);
          if (t['expect-fail'] as bool) {
            expect(
              () => lib.pasetoV4LocalDecrypt(
                t['token'] as String,
                k,
                expectedFooter: footer,
                implicit: implicit,
              ),
              invalid(),
              reason: name,
            );
            rejected++;
            continue;
          }
          expect(
            utf8.decode(
              lib.pasetoV4LocalDecrypt(
                t['token'] as String,
                k,
                expectedFooter: footer,
                implicit: implicit,
              ),
            ),
            t['payload'],
            reason: name,
          );
          decrypted++;
        }
        expect(decrypted, 9);
        expect(rejected, 4);
      },
    );
  });

  group('cb1', () {
    test('cb1.local round trips and the two formats reject each other', () {
      final m = bytes('{"data":"x"}');
      final tok = lib.cb1LocalEncrypt(
        key,
        m,
        footer: bytes('f'),
        implicit: bytes('i'),
      );
      expect(tok, startsWith('cb1.local.'));
      expect(
        lib.cb1LocalDecrypt(
          tok,
          key,
          expectedFooter: bytes('f'),
          implicit: bytes('i'),
        ),
        m,
      );
      expect(
        () => lib.cb1LocalDecrypt(
          tok,
          other,
          expectedFooter: bytes('f'),
          implicit: bytes('i'),
        ),
        invalid(),
      );
      for (final pos in [0, 5, 12, 40, tok.length - 1]) {
        final sub = tok[pos] == 'A' ? 'B' : 'A';
        expect(
          () => lib.cb1LocalDecrypt(
            tok.replaceRange(pos, pos + 1, sub),
            key,
            expectedFooter: bytes('f'),
            implicit: bytes('i'),
          ),
          invalid(),
        );
      }
      expect(
        () => lib.cb1LocalDecrypt(lib.pasetoV4LocalEncrypt(key, m), key),
        invalid(),
      );
      expect(
        () => lib.pasetoV4LocalDecrypt(lib.cb1LocalEncrypt(key, m), key),
        invalid(),
      );
    });

    test('cb1.public signs with the hybrid key and both halves are required', () {
      final kp = lib.hybridSigKeygen();
      final stranger = lib.hybridSigKeygen();
      expect(kp.publicKey.length, 1984);
      expect(kp.secretKey.length, 4096);
      final m = bytes('{"sub":"alice"}');
      final tok = lib.cb1PublicSign(
        kp.secretKey,
        m,
        footer: bytes('k1'),
        implicit: bytes('aud'),
      );
      expect(tok, startsWith('cb1.public.'));
      expect(
        lib.cb1PublicVerify(
          tok,
          kp.publicKey,
          expectedFooter: bytes('k1'),
          implicit: bytes('aud'),
        ),
        m,
      );
      expect(
        () => lib.cb1PublicVerify(
          tok,
          stranger.publicKey,
          expectedFooter: bytes('k1'),
          implicit: bytes('aud'),
        ),
        invalid(),
      );
      expect(
        () => lib.cb1PublicVerify(
          tok,
          kp.publicKey,
          expectedFooter: bytes('k2'),
          implicit: bytes('aud'),
        ),
        invalid(),
      );
      expect(
        () =>
            lib.cb1PublicVerify(tok, kp.publicKey, expectedFooter: bytes('k1')),
        invalid(),
      );
      final body = tok.substring(11, tok.indexOf('.', 11));
      final raw = base64Url.decode(base64Url.normalize(body));
      expect(raw.length, m.length + 3373);
      for (final pos in [
        0,
        m.length,
        m.length + 63,
        m.length + 64,
        raw.length - 1,
      ]) {
        final x = Uint8List.fromList(raw);
        x[pos] ^= 1;
        final forged =
            'cb1.public.${base64Url.encode(x).replaceAll('=', '')}.${base64Url.encode(bytes('k1')).replaceAll('=', '')}';
        expect(
          () => lib.cb1PublicVerify(
            forged,
            kp.publicKey,
            expectedFooter: bytes('k1'),
            implicit: bytes('aud'),
          ),
          invalid(),
        );
      }
      expect(() => lib.cb1PublicSign(Uint8List(64), m), argument());
    });

    test('the pinned cb1 vectors decrypt and verify', () {
      if (isWeb) {
        return;
      }
      Uint8List unhex(String h) => Uint8List.fromList(
        List.generate(
          h.length ~/ 2,
          (i) => int.parse(h.substring(2 * i, 2 * i + 2), radix: 16),
        ),
      );
      Uint8List? opt(Object? s) => (s as String).isEmpty ? null : bytes(s);
      final v =
          jsonDecode(
                File(
                  '../../../tests/vectors/cb1/vectors.json',
                ).readAsStringSync(),
              )
              as Map;
      final local = (v['local'] as List).cast<Map>();
      final public = (v['public'] as List).cast<Map>();
      expect(local.length, greaterThanOrEqualTo(10));
      expect(public.length, greaterThanOrEqualTo(8));
      for (final t in local) {
        final k = unhex(t['key'] as String);
        if (t['expect-fail'] as bool) {
          expect(
            () => lib.cb1LocalDecrypt(
              t['token'] as String,
              k,
              expectedFooter: opt(t['footer']),
              implicit: opt(t['implicit-assertion']),
            ),
            invalid(),
            reason: t['name'] as String,
          );
          continue;
        }
        expect(
          utf8.decode(
            lib.cb1LocalDecrypt(
              t['token'] as String,
              k,
              expectedFooter: opt(t['footer']),
              implicit: opt(t['implicit-assertion']),
            ),
          ),
          t['payload'],
          reason: t['name'] as String,
        );
      }
      for (final t in public) {
        final pk = unhex(t['public-key'] as String);
        if (t['expect-fail'] as bool) {
          expect(
            () => lib.cb1PublicVerify(
              t['token'] as String,
              pk,
              expectedFooter: opt(t['footer']),
              implicit: opt(t['implicit-assertion']),
            ),
            invalid(),
            reason: t['name'] as String,
          );
          continue;
        }
        expect(
          utf8.decode(
            lib.cb1PublicVerify(
              t['token'] as String,
              pk,
              expectedFooter: opt(t['footer']),
              implicit: opt(t['implicit-assertion']),
            ),
          ),
          t['payload'],
          reason: t['name'] as String,
        );
        final again = lib.cb1PublicSign(
          unhex(t['secret-key'] as String),
          bytes(t['payload'] as String),
          footer: opt(t['footer']),
          implicit: opt(t['implicit-assertion']),
        );
        expect(
          utf8.decode(
            lib.cb1PublicVerify(
              again,
              pk,
              expectedFooter: opt(t['footer']),
              implicit: opt(t['implicit-assertion']),
            ),
          ),
          t['payload'],
        );
      }
    });
  });

  group('keyed BLAKE2b', () {
    test(
      'matches the libsodium known answers, allocating or into a buffer',
      () {
        String hex(Uint8List b) =>
            b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
        expect(
          hex(lib.blake2bKeyed(counting(31, 0), key: counting(32, 0))),
          'a9f51bb7f6a3e9cdb96ce652c07d177962a348a9cced1b92f948187e59b44463',
        );
        expect(
          hex(lib.blake2bKeyed(bytes('abc'))),
          'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319',
        );
        expect(hex(lib.blake2bKeyed(bytes('abc'), outLen: 1)), '6b');
        final out = Uint8List(32);
        expect(
          lib.blake2bKeyedInto(out, counting(31, 0), key: counting(32, 0)),
          same(out),
        );
        expect(
          hex(out),
          'a9f51bb7f6a3e9cdb96ce652c07d177962a348a9cced1b92f948187e59b44463',
        );
        expect(
          () => lib.blake2bKeyed(bytes('m'), key: counting(15, 0)),
          throwsException,
        );
        expect(
          () => lib.blake2bKeyedInto(Uint8List(65), bytes('m')),
          argument(),
        );
        expect(hex(lib.hash.blake2bKeyed(bytes('abc'), outLen: 1)), '6b');
      },
    );
  });

  test('the tokens facade reaches the same calls', () {
    final tok = lib.tokens.v4LocalEncrypt(key, bytes('ns'));
    expect(utf8.decode(lib.tokens.v4LocalDecrypt(tok, key)), 'ns');
    expect(
      utf8.decode(
        lib.tokens.cb1LocalDecrypt(
          lib.tokens.cb1LocalEncrypt(key, bytes('cb')),
          key,
        ),
      ),
      'cb',
    );
    final kp = lib.hybridSigKeygen();
    expect(
      utf8.decode(
        lib.tokens.cb1PublicVerify(
          lib.tokens.cb1PublicSign(kp.secretKey, bytes('pub')),
          kp.publicKey,
        ),
      ),
      'pub',
    );
  });
}
