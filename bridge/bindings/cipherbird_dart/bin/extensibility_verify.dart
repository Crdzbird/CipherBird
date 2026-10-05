// The three extension points — custom ProtectionLayer / CascadeLayer, custom
// KeySource, custom SignatureScheme — and the guardrails around them.
//   dart run bin/extensibility_verify.dart [path-to-libcipherbird.dylib]
import 'dart:io';
import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';

int _f = 0;
void check(bool ok, String l) {
  stdout.writeln('${ok ? "  ok  " : " FAIL "} $l');
  if (!ok) _f++;
}

bool throwsWith(void Function() f, [String? needle]) {
  try {
    f();
    return false;
  } catch (e) {
    return needle == null || '$e'.contains(needle);
  }
}

bool eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Uint8List b(String s) => Uint8List.fromList(s.codeUnits);

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

class BeltAndBraces extends CascadeLayer {
  const BeltAndBraces()
    : super(
        id: 201,
        wireName: 'belt-and-braces',
        layers: const [XChaCha20Layer(), Aes256GcmLayer(), MyLayer()],
      );
}

class Nested extends CascadeLayer {
  const Nested()
    : super(
        id: 202,
        wireName: 'nested',
        layers: const [BeltAndBraces(), CommittingLayer()],
      );
}

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

void main(List<String> args) {
  final lib = CipherBird.load(args.isNotEmpty ? args[0] : null);
  lib.init();
  final secret = b('the treaty text nobody may read');
  Uint8List key() => lib.randomBytes(32);

  check(
    ProtectionLayer.xchacha20Poly1305.id == 1 &&
        ProtectionLayer.aes256Gcm.id == 2 &&
        ProtectionLayer.committing.id == 3 &&
        ProtectionLayer.molecular.id == 4 &&
        const PassphraseKeySource('x').id == 1 &&
        const Ed25519Signature().id == 1 &&
        const HybridSignature().id == 2,
    'built-in wire ids are pinned',
  );

  ProtectionLayer.register(const MyLayer());
  var k = key();
  var env = lib.recipe().withKey(k).withLayers([const MyLayer()]).seal(secret);
  check(
    eq(lib.recipe().withKey(k).open(env), secret),
    'custom layer round-trips via the registry',
  );

  ProtectionLayer.register(const BeltAndBraces());
  k = key();
  final r = lib.recipe().withKey(k).withLayers([const BeltAndBraces()]);
  env = r.seal(secret);
  check(
    eq(lib.recipe().withKey(k).open(env), secret),
    'CascadeLayer: three ciphers as one custom class',
  );
  final bad = Uint8List.fromList(env)..[env.length - 1] ^= 1;
  check(throwsWith(() => r.open(bad)), 'cascade fails closed on tamper');

  ProtectionLayer.register(const Nested());
  k = key();
  check(
    eq(
      lib
          .recipe()
          .withKey(k)
          .open(
            lib
                .recipe()
                .withKey(k)
                .withLayers([ProtectionLayer.xchacha20Poly1305, const Nested()])
                .seal(secret),
          ),
      secret,
    ),
    'cascades nest and mix with built-ins',
  );

  check(
    throwsWith(() => ProtectionLayer.register(const Impostor()), 'reserved'),
    'reserved id refused at register',
  );
  check(
    throwsWith(
      () => lib.recipe().withKey(key()).addLayer(const Impostor()),
      'reserved',
    ),
    'reserved id refused at addLayer',
  );
  ProtectionLayer.register(const MyLayer());
  check(
    throwsWith(
      () => ProtectionLayer.register(
        const CascadeLayer(
          id: 200,
          wireName: 'other',
          layers: [XChaCha20Layer()],
        ),
      ),
      'already registered',
    ),
    're-registering an id under another name refused',
  );

  k = key();
  final e1 = lib.recipe().withKey(k).withLayers([const MyLayer()]).seal(secret);
  final e2 = lib
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
  check(
    e1.length == e2.length && !eq(e1, e2),
    'wireName feeds the key derivation',
  );

  final token = key();
  env = lib
      .recipe(SecurityProfile.high)
      .withKeySource(TokenSource(token))
      .seal(secret);
  check(
    eq(
      lib
          .recipe(SecurityProfile.high)
          .withKeySource(TokenSource(token))
          .open(env),
      secret,
    ),
    'custom KeySource round-trips',
  );
  check(
    throwsWith(
      () => lib
          .recipe(SecurityProfile.high)
          .withKeySource(TokenSource(key()))
          .open(env),
    ),
    'wrong token rejected',
  );
  check(
    throwsWith(
      () => lib.recipe().withKey(key()).open(env),
      'key source id 210',
    ),
    'header pins the source id',
  );
  check(
    throwsWith(
      () => lib.recipe().withKeySource(const WeakSource()).seal(secret),
      'must be exactly 32',
    ),
    'narrowing source refused',
  );

  final id = lib.ed25519Keygen();
  k = key();
  env = lib
      .recipe()
      .withKey(k)
      .signedWith(PrefixedEd25519(sk: id.secretKey))
      .seal(secret);
  check(
    eq(
      lib
          .recipe()
          .withKey(k)
          .verifiedWith(PrefixedEd25519(pk: id.publicKey))
          .open(env),
      secret,
    ),
    'custom SignatureScheme round-trips',
  );
  check(
    throwsWith(
      () => lib.recipe().withKey(k).verifiedBy(id.publicKey).open(env),
      'scheme id 220',
    ),
    'key-only verifier cannot serve a custom scheme',
  );
  check(
    throwsWith(() => lib.recipe().withKey(k).open(env)),
    'unverified signed envelope refused',
  );
  check(
    throwsWith(
      () => lib.recipe().withKey(key()).signedWith(const FakeEd25519()),
      'reserved',
    ),
    'scheme claiming a built-in id refused',
  );

  final hid = lib.hybridSigKeygen();
  k = key();
  final hr = lib
      .recipe()
      .withKey(k)
      .signedBy(hid.secretKey, algorithm: SignatureAlgorithm.hybrid)
      .verifiedBy(hid.publicKey);
  check(
    eq(hr.open(hr.seal(secret)), secret),
    'built-in shorthands still work (algorithm from envelope)',
  );

  final text = lib.recipe().withKeySource(TokenSource(key())).withLayers([
    const BeltAndBraces(),
  ]).describe();
  check(
    text.contains('token') && text.contains('belt-and-braces'),
    'describe() names custom parts',
  );

  stdout.writeln(_f == 0 ? '\nALL PASS' : '\n$_f FAILURE(S)');
  exit(_f == 0 ? 0 : 1);
}
