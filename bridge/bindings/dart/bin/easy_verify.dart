// Easy mode verifier for the standalone package (mirror of the Flutter
// test/easy_test.dart). Run from the repo root: dart run bridge/bindings/dart/bin/easy_verify.dart [dylib]
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

var _pass = 0, _fail = 0;
void test(String name, void Function() body) {
  try {
    body();
    _pass++;
    print('  ok   $name');
  } catch (e) {
    _fail++;
    print(' FAIL  $name: $e');
  }
}

void group(String name, void Function() body) => body();
void expect(Object? actual, Object? matcher, {String? reason}) {
  final ok = switch (matcher) {
    _Matcher m => m.test(actual),
    List<int> l when actual is List<int> => l.length == actual.length &&
        () {
          for (var i = 0; i < l.length; i++) {
            if (l[i] != actual[i]) return false;
          }
          return true;
        }(),
    _ => actual == matcher,
  };
  if (!ok)
    throw StateError(
        'expected $matcher, got $actual${reason == null ? '' : ' ($reason)'}');
}

abstract class _Matcher {
  bool test(Object? v);
}

class _Not extends _Matcher {
  _Not(this.inner);
  final Object? inner;
  @override
  bool test(Object? v) =>
      inner is _Matcher ? !(inner as _Matcher).test(v) : v != inner;
}

class _Throws extends _Matcher {
  _Throws(this.arg);
  final Object? arg;
  @override
  bool test(Object? v) {
    try {
      (v! as Function)();
      return false;
    } catch (e) {
      return arg == null ||
          arg is! Type ||
          e.runtimeType == arg ||
          (arg == ArgumentError && e is ArgumentError);
    }
  }
}

class _Is<T> extends _Matcher {
  @override
  bool test(Object? v) => v is T;
}

class _Pred extends _Matcher {
  _Pred(this.p);
  final bool Function(Object?) p;
  @override
  bool test(Object? v) => p(v);
}

_Matcher isNot(Object? m) => _Not(m);
_Matcher throwsA(Object? _) => _Throws(null);
final throwsArgumentError = _Throws(ArgumentError);
_Matcher isA<T>() => _Is<T>();
final isTrue = _Pred((v) => v == true), isFalse = _Pred((v) => v == false);
final isNotEmpty = _Pred((v) => (v as dynamic).isNotEmpty == true),
    isEmpty = _Pred((v) => (v as dynamic).isEmpty == true);
_Matcher startsWith(String s) => _Pred((v) => v is String && v.startsWith(s));
_Matcher contains(Object s) => _Pred((v) => (v as dynamic).contains(s) == true);
const anything = null;

void main(List<String> args) {
  final lib = CryptoLib.load(
      args.isNotEmpty ? args[0] : 'build/release/libcryptolib_c.dylib')
    ..init();

  group('bytes & text sugar', () {
    test('utf8 / hex / base64 round-trip', () {
      expect('héllo'.bytes.text, 'héllo');
      expect('abc'.bytes.hex, '616263');
      expect('616263'.hexBytes.text, 'abc');
      expect('abc'.bytes.base64, 'YWJj');
      expect('YWJj'.base64Bytes.text, 'abc');
      expect('YQ'.base64Bytes.text, 'a'); // unpadded input is normalised
      expect(Uint8List.fromList([0xfb, 0xff]).base64Url,
          '-_8'); // url-safe, unpadded
    });

    test('constantTimeEquals / concat / wipe / u8', () {
      final a = 'tag'.bytes;
      expect(a.constantTimeEquals('tag'.bytes), isTrue);
      expect(a.constantTimeEquals('tah'.bytes), isFalse);
      expect(a.constantTimeEquals('ta'.bytes), isFalse);
      expect(a.concat('s'.bytes).text, 'tags');
      expect([1, 2, 3].u8, isA<Uint8List>());
      final k = lib.randomBytes(8)..wipe();
      expect(k.every((b) => b == 0), isTrue);
    });

    test('sha256Hex and KeyPairText', () {
      expect(lib.easy.sha256Hex('abc'),
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
      final kp = lib.ed25519Keygen();
      expect(kp.publicHex, kp.publicKey.hex);
      expect(kp.secretHex.length, 128);
    });
  });

  group('SymmetricKey', () {
    test('generate / encrypt / decrypt with aad, text form', () {
      final key = SymmetricKey.generate();
      final ct = key.encrypt('meet at dawn'.bytes, aad: 'ctx'.bytes);
      expect(key.decrypt(ct, aad: 'ctx'.bytes).text, 'meet at dawn');
      expect(() => key.decrypt(ct, aad: 'other'.bytes), throwsA(anything));
      expect(() => SymmetricKey.generate().decrypt(ct, aad: 'ctx'.bytes),
          throwsA(anything));
      final box = key.encryptText('hello', aad: 'h');
      expect(key.decryptText(box, aad: 'h'), 'hello');
    });

    test('serialises and reloads', () {
      final key = SymmetricKey.generate();
      final ct = key.encryptText('x');
      expect(SymmetricKey.fromHex(key.hex).decryptText(ct), 'x');
      expect(SymmetricKey.fromBase64(key.base64).decryptText(ct), 'x');
      expect(SymmetricKey.fromBytes(key.bytes).decryptText(ct), 'x');
      expect(() => SymmetricKey.fromBytes(Uint8List(16)), throwsArgumentError);
    });

    test('passphrase is deterministic per salt and cheap cost is honoured', () {
      final salt = lib.easy.randomBytes(16);
      SymmetricKey mk(String p) => SymmetricKey.fromPassphrase(p,
          salt: salt, ops: 1, memoryBytes: 8 * 1024 * 1024);
      final ct = mk('correct horse').encryptText('secret');
      expect(mk('correct horse').decryptText(ct), 'secret');
      expect(() => mk('wrong horse').decryptText(ct), throwsA(anything));
      expect(() => SymmetricKey.fromPassphrase('p', salt: Uint8List(8)),
          throwsArgumentError);
    });

    test('derive gives independent, stable sub-keys', () {
      final root = SymmetricKey.generate();
      expect(root.derive('db').hex, root.derive('db').hex);
      expect(root.derive('db').hex, isNot(root.derive('cache').hex));
      expect(root.derive('db').hex, isNot(root.hex));
    });

    test('plugs into a recipe as a key source', () {
      final key = SymmetricKey.generate();
      final env = lib.recipe().withKeySource(key.asKeySource).seal('r'.bytes);
      expect(lib.recipe().withKey(key.bytes).open(env).text, 'r');
    });

    test('destroy wipes the key', () {
      final key = SymmetricKey.generate()..destroy();
      expect(key.bytes.every((b) => b == 0), isTrue);
    });
  });

  group('SigningKey / VerifyKey', () {
    for (final algo in [
      SignatureAlgorithm.ed25519,
      SignatureAlgorithm.hybrid
    ]) {
      test('$algo sign / verify, text form, hex reload', () {
        final key = SigningKey.generate(algorithm: algo);
        final sig = key.sign('msg'.bytes);
        expect(key.verify('msg'.bytes, sig), isTrue);
        expect(key.verify('msh'.bytes, sig), isFalse);
        final vk = VerifyKey.fromHex(key.publicKey.hex, algorithm: algo);
        expect(vk.verifyText('release', key.signText('release')), isTrue);
        expect(
            vk.verifyText('release',
                SigningKey.generate(algorithm: algo).signText('release')),
            isFalse);
        final reloaded = SigningKey.fromBytes(
            secretKey: key.secretKey,
            publicKey: key.publicKey,
            algorithm: algo);
        expect(
            key.verifyKey.verify('m'.bytes, reloaded.sign('m'.bytes)), isTrue);
      });
    }

    test('none is refused', () {
      expect(() => SigningKey.generate(algorithm: SignatureAlgorithm.none),
          throwsArgumentError);
    });

    test('scheme plugs into a recipe', () {
      final key = SigningKey.generate(algorithm: SignatureAlgorithm.hybrid);
      final k = SymmetricKey.generate();
      final env =
          lib.recipe().withKey(k.bytes).signedWith(key.scheme).seal('r'.bytes);
      expect(
          lib
              .recipe()
              .withKey(k.bytes)
              .verifiedWith(key.verifyKey.scheme)
              .open(env)
              .text,
          'r');
      expect(
          lib
              .recipe()
              .withKey(k.bytes)
              .verifiedBy(key.publicKey)
              .open(env)
              .text,
          'r');
    });
  });

  group('KemKeyPair', () {
    test('encapsulate / decapsulate agree on a key', () {
      final me = KemKeyPair.generate();
      final (ct, key) = KemKeyPair.encapsulate(me.publicKey);
      expect(me.decapsulate(ct).hex, key.hex);
      expect(KemKeyPair.generate().decapsulate(ct).hex, isNot(key.hex));
    });

    test('one-call public-key encryption, bytes and text, with aad', () {
      final me = KemKeyPair.generate();
      final blob = KemKeyPair.encryptFor(me.publicKey, 'for your eyes'.bytes,
          aad: 'a'.bytes);
      expect(me.decrypt(blob, aad: 'a'.bytes).text, 'for your eyes');
      expect(() => me.decrypt(blob, aad: 'b'.bytes), throwsA(anything));
      expect(() => KemKeyPair.generate().decrypt(blob, aad: 'a'.bytes),
          throwsA(anything));
      final text = KemKeyPair.encryptTextFor(me.publicKey, 'hi');
      expect(me.decryptText(text), 'hi');
      final tampered = Uint8List.fromList(blob)..[blob.length - 1] ^= 1;
      expect(() => me.decrypt(tampered, aad: 'a'.bytes), throwsA(anything));
      expect(() => me.decrypt(Uint8List(3)), throwsArgumentError);
    });

    test('reloads from bytes', () {
      final me = KemKeyPair.generate();
      final blob = KemKeyPair.encryptFor(me.publicKey, 'x'.bytes);
      final again = KemKeyPair.fromBytes(
          publicKey: me.publicKey, secretKey: me.secretKey);
      expect(again.decrypt(blob).text, 'x');
    });
  });

  group('lib.easy', () {
    test('factories, randomness, tokens', () {
      expect(lib.easy.symmetricKey().bytes.length, 32);
      expect(lib.easy.signingKey().publicKey.length, 32);
      expect(lib.easy.kemKeyPair().publicKey, isNotEmpty);
      expect(lib.easy.randomHex(16).length, 32);
      expect(lib.easy.token(), isNot(lib.easy.token()));
      expect(lib.easy.token(), isNot(contains('=')));
    });

    test('password hashing round-trip (cheap profile)', () {
      final phc = lib.easy.hashPassword('hunter2');
      expect(phc, startsWith(r'$argon2id$'));
      expect(lib.easy.verifyPassword('hunter2', phc), isTrue);
      expect(lib.easy.verifyPassword('hunter3', phc), isFalse);
    });

    test('identity text sugar', () {
      final alice = lib.easy.identity(SealedTier.fortress),
          bob = lib.easy.identity(SealedTier.fortress);
      final env = bob.sealText('meet at dawn',
          to: alice.recipientPublic, purpose: 'note');
      expect(alice.openText(env, from: bob.senderPublic, purpose: 'note'),
          'meet at dawn');
      expect(
          () => alice.openText(env, from: bob.senderPublic, purpose: 'other'),
          throwsA(anything));
    });
  });

  print(
      _fail == 0 ? 'ALL PASS ($_pass)' : 'FAILED ($_fail of ${_pass + _fail})');
  if (_fail != 0) throw StateError('easy verify failed');
}
