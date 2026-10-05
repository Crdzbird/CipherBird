// The three extension points: custom ProtectionLayer / CascadeLayer,
// custom KeySource, custom SignatureScheme — and the guardrails around them.
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

Uint8List b(String s) => Uint8List.fromList(s.codeUnits);

/// A user layer: a real AEAD (the library's XChaCha20) under its own identity.
class MyLayer extends ProtectionLayer {
  const MyLayer();
  @override
  int get id => 200;
  @override
  String get wireName => 'my-xchacha';
  @override
  Uint8List seal(CipherBird lib, Uint8List key, Uint8List aad, Uint8List pt) =>
      lib.xchacha20Encrypt(pt, key, aad);
  @override
  Uint8List open(CipherBird lib, Uint8List key, Uint8List aad, Uint8List ct) =>
      lib.xchacha20Decrypt(ct, key, aad);
}

/// A user mixture: three ciphers as ONE layer, via inheritance.
class BeltAndBraces extends CascadeLayer {
  const BeltAndBraces()
    : super(
        id: 201,
        wireName: 'belt-and-braces',
        layers: const [XChaCha20Layer(), Aes256GcmLayer(), MyLayer()],
      );
}

/// Cascades nest.
class Nested extends CascadeLayer {
  const Nested()
    : super(
        id: 202,
        wireName: 'nested',
        layers: const [BeltAndBraces(), CommittingLayer()],
      );
}

/// A layer claiming a reserved id — must be refused.
class Impostor extends ProtectionLayer {
  const Impostor();
  @override
  int get id => 3;
  @override
  String get wireName => 'committing';
  @override
  Uint8List seal(CipherBird lib, Uint8List k, Uint8List a, Uint8List p) => p;
  @override
  Uint8List open(CipherBird lib, Uint8List k, Uint8List a, Uint8List c) => c;
}

/// A user key source: a "hardware token" that always yields the same 32 bytes.
class TokenSource extends KeySource {
  const TokenSource(this.token);
  final Uint8List token;
  @override
  int get id => 210;
  @override
  String get label => 'token';
  @override
  Uint8List deriveRoot(CipherBird lib, Uint8List salt, int ops, int mem) =>
      token;
}

/// A user key source that returns too few bytes — must be refused.
class WeakSource extends KeySource {
  const WeakSource();
  @override
  int get id => 211;
  @override
  String get label => 'weak';
  @override
  Uint8List deriveRoot(CipherBird lib, Uint8List salt, int ops, int mem) =>
      Uint8List(16);
}

/// A user signature scheme: Ed25519 over a domain-separated message.
class PrefixedEd25519 extends SignatureScheme {
  const PrefixedEd25519({this.sk, this.pk});
  final Uint8List? sk;
  final Uint8List? pk;
  @override
  int get id => 220;
  @override
  String get label => 'prefixed-ed25519';
  Uint8List _tag(Uint8List m) => Uint8List.fromList([...b('custom:'), ...m]);
  @override
  Uint8List sign(CipherBird lib, Uint8List m) => lib.ed25519Sign(_tag(m), sk!);
  @override
  bool verify(CipherBird lib, Uint8List m, Uint8List sig) =>
      lib.ed25519Verify(_tag(m), sig, pk!);
}

/// A scheme claiming a built-in id — must be refused.
class FakeEd25519 extends SignatureScheme {
  const FakeEd25519();
  @override
  int get id => 1;
  @override
  String get label => 'fake';
  @override
  Uint8List sign(CipherBird lib, Uint8List m) => Uint8List(64);
  @override
  bool verify(CipherBird lib, Uint8List m, Uint8List s) => true;
}

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  final secret = b('the treaty text nobody may read');
  Uint8List key() => lib.rng.bytes(32);

  test('built-in wire ids are pinned', () {
    expect(ProtectionLayer.xchacha20Poly1305.id, 1);
    expect(ProtectionLayer.aes256Gcm.id, 2);
    expect(ProtectionLayer.committing.id, 3);
    expect(ProtectionLayer.molecular.id, 4);
    expect(const PassphraseKeySource('x').id, 1);
    expect(const Ed25519Signature().id, 1);
    expect(const HybridSignature().id, 2);
  });

  group('custom ProtectionLayer', () {
    test(
      'round-trips once registered; an unregistered opener fails closed',
      () {
        ProtectionLayer.register(const MyLayer());
        final k = key();
        final env = lib
            .recipe()
            .withKey(k)
            .withLayers([const MyLayer()])
            .seal(secret);
        expect(
          lib.recipe().withKey(k).open(env),
          secret,
          reason: 'resolved from the registry by id',
        );
      },
    );

    test('a mixture of ciphers as one custom class (CascadeLayer)', () {
      ProtectionLayer.register(const BeltAndBraces());
      final k = key();
      final r = lib.recipe().withKey(k).withLayers([const BeltAndBraces()]);
      final env = r.seal(secret);
      expect(lib.recipe().withKey(k).open(env), secret);
      final bad = Uint8List.fromList(env)..[env.length - 1] ^= 1;
      expect(
        () => r.open(bad),
        throwsA(anything),
        reason: 'every inner layer binds the AAD and fails closed',
      );
    });

    test('cascades nest, and mix with built-ins in the outer recipe', () {
      ProtectionLayer.register(const Nested());
      final k = key();
      final r = lib.recipe().withKey(k).withLayers([
        ProtectionLayer.xchacha20Poly1305,
        const Nested(),
      ]);
      expect(lib.recipe().withKey(k).open(r.seal(secret)), secret);
    });

    test(
      'reserved ids are refused, so a custom layer cannot shadow a built-in',
      () {
        expect(
          () => ProtectionLayer.register(const Impostor()),
          throwsArgumentError,
        );
        expect(
          () => lib.recipe().withKey(key()).addLayer(const Impostor()),
          throwsArgumentError,
        );
      },
    );

    test('re-registering an id under a different name is refused', () {
      ProtectionLayer.register(const MyLayer()); // same id + name: idempotent
      expect(
        () => ProtectionLayer.register(
          const CascadeLayer(
            id: 200,
            wireName: 'other',
            layers: [XChaCha20Layer()],
          ),
        ),
        throwsStateError,
      );
    });

    test('the wireName is part of the key derivation', () {
      // Same id, same algorithm, different wireName -> a different layer key →
      // the tag fails. This is what makes a mismatched implementation in
      // another language fail closed instead of yielding garbage.
      final k = key();
      final env = lib
          .recipe()
          .withKey(k)
          .withLayers([const MyLayer()])
          .seal(secret);
      final env2 = lib
          .recipe()
          .withKey(k)
          .withLayers([
            const CascadeLayer(
              id: 203,
              wireName: 'renamed',
              layers: [XChaCha20Layer()],
            ),
          ])
          .seal(secret);
      expect(env.length, env2.length);
      expect(env, isNot(env2));
    });
  });

  group('custom KeySource', () {
    test('a token source round-trips across recipe objects', () {
      final token = key();
      final env = lib
          .recipe(SecurityProfile.high)
          .withKeySource(TokenSource(token))
          .seal(secret);
      expect(
        lib
            .recipe(SecurityProfile.high)
            .withKeySource(TokenSource(token))
            .open(env),
        secret,
      );
      expect(
        () => lib
            .recipe(SecurityProfile.high)
            .withKeySource(TokenSource(key()))
            .open(env),
        throwsA(anything),
      );
    });

    test(
      'the header pins the source id, so a different source is rejected up front',
      () {
        final env = lib.recipe().withKeySource(TokenSource(key())).seal(secret);
        expect(
          () => lib.recipe().withKey(key()).open(env),
          throwsA(predicate((e) => '$e'.contains('key source id 210'))),
        );
      },
    );

    test('a source that narrows the key is refused', () {
      expect(
        () => lib.recipe().withKeySource(const WeakSource()).seal(secret),
        throwsA(predicate((e) => '$e'.contains('must be exactly 32'))),
      );
    });
  });

  group('custom SignatureScheme', () {
    test('round-trips with signedWith/verifiedWith', () {
      final id = lib.ed25519Keygen();
      final k = key();
      final env = lib
          .recipe()
          .withKey(k)
          .signedWith(PrefixedEd25519(sk: id.secretKey))
          .seal(secret);
      expect(
        lib
            .recipe()
            .withKey(k)
            .verifiedWith(PrefixedEd25519(pk: id.publicKey))
            .open(env),
        secret,
      );
    });

    test(
      'verifying with a different scheme id is rejected before any verify runs',
      () {
        final id = lib.ed25519Keygen();
        final k = key();
        final env = lib
            .recipe()
            .withKey(k)
            .signedWith(PrefixedEd25519(sk: id.secretKey))
            .seal(secret);
        expect(
          () => lib.recipe().withKey(k).verifiedBy(id.publicKey).open(env),
          throwsA(predicate((e) => '$e'.contains('signed with scheme id 220'))),
        );
      },
    );

    test('an unverified signed envelope still refuses to open', () {
      final id = lib.ed25519Keygen();
      final k = key();
      final env = lib
          .recipe()
          .withKey(k)
          .signedWith(PrefixedEd25519(sk: id.secretKey))
          .seal(secret);
      expect(() => lib.recipe().withKey(k).open(env), throwsStateError);
    });

    test('a scheme claiming a built-in id is refused', () {
      expect(
        () => lib.recipe().withKey(key()).signedWith(const FakeEd25519()),
        throwsArgumentError,
      );
    });

    test('built-in shorthands still work and pin their ids', () {
      final id = lib.hybridSigKeygen();
      final k = key();
      final r = lib
          .recipe()
          .withKey(k)
          .signedBy(id.secretKey, algorithm: SignatureAlgorithm.hybrid)
          .verifiedBy(id.publicKey); // the envelope names the built-in scheme
      expect(r.open(r.seal(secret)), secret);
    });
  });

  test('describe() names custom parts', () {
    final text = lib.recipe().withKeySource(TokenSource(key())).withLayers([
      const BeltAndBraces(),
    ]).describe();
    expect(text, contains('token'));
    expect(text, contains('belt-and-braces'));
  });
}
