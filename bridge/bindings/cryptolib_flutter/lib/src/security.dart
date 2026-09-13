part of 'cryptolib.dart';

// CryptoRecipe is a deliberate fluent builder: each configuration step returns
// the same instance so a recipe reads as one declaration. That is exactly what
// avoid_returning_this warns about, so it is disabled here on purpose.
// ignore_for_file: avoid_returning_this

// ── Security profiles and composable recipes ─────────────────────────────────
//
// Two things live here:
//
//   * [SecurityProfile] — one choice that sets every algorithm parameter
//     consistently, so "use the strongest thing available" is a single word
//     rather than a dozen correct-but-easily-mismatched constants.
//
//   * [CryptoRecipe] — a declarative way to stack the library's protections in
//     combination: derive a key, cascade several AEADs, sign, add error
//     correction, hide the result in a carrier.
//
// Composition only — every step is an existing, vetted operation. What the
// recipe adds is the plumbing that is easy to get wrong by hand:
//
//   * Every layer gets its **own** key, via HKDF with a distinct info string.
//     A key is never reused across two layers.
//   * The header describing the recipe is authenticated as AAD by **every**
//     layer, so the descriptor cannot be altered without every layer failing.
//   * Order is fixed and not caller-selectable: sign → encrypt (inner to outer)
//     → error-correct → conceal. Opening reverses it exactly.
//   * Everything fails closed. A wrong key, a tampered byte or a mismatched
//     recipe raises rather than returning partial plaintext.
//
// The envelope is a library-native format (like MolecularVault's "MVLT"), not a
// standard, and is not interoperable with other implementations.

/// A coherent set of algorithm parameters, from ordinary to maximal.
///
/// Every field moves together, so you cannot accidentally pair a maximal KEM
/// with an interactive-cost KDF. Reach for [maximum] when the data outlives the
/// threat model you can predict.
enum SecurityProfile {
  /// Sound modern defaults. Fast enough for interactive use.
  balanced,

  /// Stronger parameters and a two-cipher cascade. Noticeably slower to unlock.
  high,

  /// The strongest option the library offers at every single choice: category-5
  /// post-quantum parameter sets, the triple-family sealed tier, a
  /// three-layer cascade ending in a key-committing AEAD, and a memory-hard KDF
  /// tuned well past interactive comfort.
  maximum;

  /// ML-KEM parameter set for this profile.
  MlKemLevel get mlKem => switch (this) {
        SecurityProfile.balanced => MlKemLevel.level768,
        SecurityProfile.high => MlKemLevel.level768,
        SecurityProfile.maximum => MlKemLevel.level1024,
      };

  /// ML-DSA parameter set for this profile.
  MlDsaLevel get mlDsa => switch (this) {
        SecurityProfile.balanced => MlDsaLevel.level65,
        SecurityProfile.high => MlDsaLevel.level65,
        SecurityProfile.maximum => MlDsaLevel.level87,
      };

  /// SLH-DSA parameter set. [maximum] takes the small-signature variant: it
  /// signs more slowly but keeps signatures compact, and hash-based security is
  /// the point of using it at all.
  SlhDsaLevel get slhDsa => switch (this) {
        SecurityProfile.balanced => SlhDsaLevel.fast128,
        SecurityProfile.high => SlhDsaLevel.fast192,
        SecurityProfile.maximum => SlhDsaLevel.small256,
      };

  /// Hash family for SLH-DSA.
  SlhDsaHash get slhDsaHash =>
      this == SecurityProfile.maximum ? SlhDsaHash.shake : SlhDsaHash.sha2;

  /// Sealed-messaging tier. [maximum] uses the triple-family Fortress tier.
  SealedTier get sealedTier =>
      this == SecurityProfile.maximum ? SealedTier.fortress : SealedTier.flagship;

  /// HPKE KDF.
  HpkeKdf get hpkeKdf =>
      this == SecurityProfile.maximum ? HpkeKdf.sha512 : HpkeKdf.sha256;

  /// HPKE AEAD.
  HpkeAead get hpkeAead => HpkeAead.chaCha20Poly1305;

  /// Argon2id cost preset for vault and keyring slots.
  KdfPreset get kdfPreset =>
      this == SecurityProfile.balanced ? KdfPreset.interactive : KdfPreset.sensitive;

  /// Argon2id iteration count used by [CryptoRecipe].
  int get argon2Ops => switch (this) {
        SecurityProfile.balanced => 2,
        SecurityProfile.high => 3,
        SecurityProfile.maximum => 4,
      };

  /// Argon2id memory cost in bytes used by [CryptoRecipe].
  ///
  /// Memory is what actually costs an attacker; raise it as far as the slowest
  /// device you must support can bear.
  int get argon2Memory => switch (this) {
        SecurityProfile.balanced => 64 * 1024 * 1024,
        SecurityProfile.high => 256 * 1024 * 1024,
        SecurityProfile.maximum => 512 * 1024 * 1024,
      };

  /// The AEAD cascade this profile applies, innermost first.
  ///
  /// Independent cipher families mean a break of one does not open the
  /// envelope, and the key-committing outer layer closes partitioning-oracle
  /// and Invisible-Salamanders style attacks.
  List<ProtectionLayer> get cascade => switch (this) {
        SecurityProfile.balanced => const [ProtectionLayer.xchacha20Poly1305],
        SecurityProfile.high => const [
            ProtectionLayer.xchacha20Poly1305,
            ProtectionLayer.aes256Gcm,
          ],
        SecurityProfile.maximum => const [
            ProtectionLayer.xchacha20Poly1305,
            ProtectionLayer.aes256Gcm,
            ProtectionLayer.committing,
          ],
      };
}

// ── Extension points ─────────────────────────────────────────────────────────
//
// Three abstractions can be subclassed and plugged into a recipe:
//
//   * [ProtectionLayer]  — one authenticated-encryption layer in the cascade.
//   * [KeySource]        — where the 32-byte root key comes from.
//   * [SignatureScheme]  — how the plaintext is signed and verified.
//
// The library's own implementations are ordinary subclasses of the same
// classes, so a custom one is a first-class citizen, not a side door.
//
// What the recipe keeps for itself, whatever you plug in:
//   * A layer never chooses its key — it receives a fresh 32-byte key per layer,
//     per envelope, HKDF-derived from the root under salt + wireName.
//   * A layer cannot opt out of the AAD — the authenticated header is handed in
//     and the contract requires binding it.
//   * The order is fixed: sign → encrypt (inner to outer) → error-correct →
//     conceal. Custom parts implement one step each; they cannot reorder.
//   * A custom KeySource must return exactly 32 bytes, or the recipe refuses.
//   * Identifiers 0–127 are reserved for the library; custom parts must use
//     128–255. That is enforced, so a custom part can never shadow a built-in.
//
// Cross-language: built-in ids 1–4 open in every CryptoLib binding. A CUSTOM
// part opens only where the same id + wireName + algorithm is registered — and
// because wireName feeds the key derivation, a mismatched implementation fails
// the AEAD tag rather than yielding garbage.

/// Marks the library's own implementations. Library-private, so a custom
/// subclass cannot claim a reserved identifier by pretending to be built in.
mixin _Builtin {}

const int _customIdMin = 128;
const int _customIdMax = 255;

void _requireValidId(Object part, int id, String what) {
  if (part is _Builtin) return;
  if (id < _customIdMin || id > _customIdMax) {
    throw ArgumentError.value(
      id, 'id', 'custom $what ids must be in $_customIdMin..$_customIdMax (0–127 are reserved)');
  }
}

/// One authenticated-encryption layer in a [CryptoRecipe] cascade.
///
/// Subclass it to add your own layer, then [ProtectionLayer.register] it (on
/// the opening side too — the envelope stores only the [ProtectionLayer.id]):
///
/// ```dart
/// class MyLayer extends ProtectionLayer {
///   const MyLayer();
///   @override int get id => 200;
///   @override String get wireName => 'my-layer';
///   @override Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) =>
///       lib.xchacha20Encrypt(pt, key, aad);
///   @override Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) =>
///       lib.xchacha20Decrypt(ct, key, aad);
/// }
/// ProtectionLayer.register(const MyLayer());
/// ```
///
/// **Contract:** [seal] must be authenticated encryption that binds `aad`, and
/// [open] must fail closed on any modification of ciphertext or aad. The
/// `key` is fresh per layer per envelope — never reuse it elsewhere. To build
/// a layer out of several ciphers, extend [CascadeLayer] instead.
abstract class ProtectionLayer {
  const ProtectionLayer();

  /// XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
  static const ProtectionLayer xchacha20Poly1305 = XChaCha20Layer();

  /// AES-256-GCM. A different cipher family from ChaCha.
  static const ProtectionLayer aes256Gcm = Aes256GcmLayer();

  /// Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
  static const ProtectionLayer committing = CommittingLayer();

  /// A full MolecularVault (cascade + committing) nested as one layer.
  static const ProtectionLayer molecular = MolecularLayer();

  /// Identifier recorded in the envelope header. Built-ins use 1–4; custom
  /// layers must use 128–255.
  int get id;

  /// Name used in this layer's HKDF info string. Part of the wire format:
  /// change it and every existing envelope using this layer stops opening.
  String get wireName;

  /// Authenticated-encrypt [plaintext] under [key], binding [aad].
  Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List plaintext);

  /// Reverse [seal]. Must throw on any modification.
  Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ciphertext);

  static final Map<int, ProtectionLayer> _registry = {
    1: xchacha20Poly1305, 2: aes256Gcm, 3: committing, 4: molecular,
  };

  /// Make a custom layer resolvable by id when opening envelopes. Required on
  /// both the sealing and the opening side. Re-registering the same id with a
  /// different implementation is refused.
  static void register(ProtectionLayer layer) {
    _requireValidId(layer, layer.id, 'layer');
    final existing = _registry[layer.id];
    if (existing != null && existing.wireName != layer.wireName) {
      throw StateError('cryptolib: layer id ${layer.id} is already registered as "${existing.wireName}"');
    }
    _registry[layer.id] = layer;
  }

  static ProtectionLayer _resolve(int id) =>
      _registry[id] ??
      (throw Exception('cryptolib: unknown protection layer id $id — register() it before opening'));

  @override
  String toString() => wireName;
}

/// XChaCha20-Poly1305 layer.
final class XChaCha20Layer extends ProtectionLayer with _Builtin {
  const XChaCha20Layer();
  @override int get id => 1;
  @override String get wireName => 'xchacha20Poly1305';
  @override Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) => lib.xchacha20Encrypt(pt, key, aad);
  @override Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) => lib.xchacha20Decrypt(ct, key, aad);
}

/// AES-256-GCM layer.
final class Aes256GcmLayer extends ProtectionLayer with _Builtin {
  const Aes256GcmLayer();
  @override int get id => 2;
  @override String get wireName => 'aes256Gcm';
  @override Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) => lib.aes256gcmEncrypt(pt, key, aad);
  @override Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) => lib.aes256gcmDecrypt(ct, key, aad);
}

/// Key-committing AEAD (UtC) layer.
final class CommittingLayer extends ProtectionLayer with _Builtin {
  const CommittingLayer();
  @override int get id => 3;
  @override String get wireName => 'committing';
  @override Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) => lib.committingEncrypt(pt, key, aad);
  @override Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) => lib.committingDecrypt(ct, key, aad);
}

/// A whole MolecularVault as one layer.
final class MolecularLayer extends ProtectionLayer with _Builtin {
  const MolecularLayer();
  @override int get id => 4;
  @override String get wireName => 'molecular';
  @override Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) => lib.molecularSealWithKey(pt, key, aad: aad);
  @override Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) => lib.molecularOpenWithKey(ct, key, aad: aad);
}

/// A layer that is itself a mixture of layers — the way to compose several
/// encryptions into one custom class:
///
/// ```dart
/// class BeltAndBraces extends CascadeLayer {
///   const BeltAndBraces() : super(id: 200, wireName: 'belt-and-braces',
///       layers: [XChaCha20Layer(), Aes256GcmLayer(), MyHsmLayer()]);
/// }
/// ```
///
/// Each inner layer receives its own sub-key, HKDF-derived from this layer's
/// key under the inner index and wireName, so nesting never collapses two
/// ciphers onto one key. The AAD is bound by every inner layer. Cascades nest.
class CascadeLayer extends ProtectionLayer {
  const CascadeLayer({required this.id, required this.wireName, required this.layers});

  @override
  final int id;
  @override
  final String wireName;

  /// Inner layers, innermost first.
  final List<ProtectionLayer> layers;

  Uint8List _subKey(CryptoLib lib, Uint8List key, int i) => lib.hkdfDerive(
        key, info: Uint8List.fromList('$wireName/$i/${layers[i].wireName}'.codeUnits));

  @override
  Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List plaintext) {
    if (layers.isEmpty) throw StateError('cryptolib: CascadeLayer "$wireName" has no layers');
    var body = plaintext;
    for (var i = 0; i < layers.length; i++) {
      body = layers[i].seal(lib, _subKey(lib, key, i), aad, body);
    }
    return body;
  }

  @override
  Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ciphertext) {
    if (layers.isEmpty) throw StateError('cryptolib: CascadeLayer "$wireName" has no layers');
    var body = ciphertext;
    for (var i = layers.length - 1; i >= 0; i--) {
      body = layers[i].open(lib, _subKey(lib, key, i), aad, body);
    }
    return body;
  }
}

/// Where a [CryptoRecipe]'s 32-byte root key comes from.
///
/// Subclass it for a hardware token, a KMS, a keyring unlock — anything that
/// can produce the same 32 bytes again when opening. The recipe refuses any
/// other length, so a weak source cannot silently narrow the key.
abstract class KeySource {
  const KeySource();

  /// Identifier recorded in the envelope header. Built-ins use 0–2; custom
  /// sources must use 128–255. Opening requires a source with the same id.
  int get id;

  /// Short name for [CryptoRecipe.describe].
  String get label;

  /// Produce the root key. [salt] is fresh per envelope and stored in the
  /// header; [argon2Ops]/[argon2Memory] are the recipe's KDF cost, for sources
  /// that stretch a low-entropy input.
  Uint8List deriveRoot(CryptoLib lib, Uint8List salt, int argon2Ops, int argon2Memory);
}

/// A 32-byte key used as-is — from a KEM shared secret, a keyring unlock, a
/// token. Nothing is stretched; the key must already be full-entropy.
final class RawKeySource extends KeySource with _Builtin {
  RawKeySource(Uint8List key) : _key = Uint8List.fromList(key) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, 'key.length', 'root key must be exactly 32 bytes');
    }
  }
  final Uint8List _key;
  @override int get id => 0;
  @override String get label => 'raw';
  @override Uint8List deriveRoot(CryptoLib lib, Uint8List salt, int ops, int mem) => _key;
}

/// A passphrase stretched with Argon2id at the recipe's cost.
final class PassphraseKeySource extends KeySource with _Builtin {
  const PassphraseKeySource(this.passphrase);
  final String passphrase;
  @override int get id => 1;
  @override String get label => 'passphrase';
  @override Uint8List deriveRoot(CryptoLib lib, Uint8List salt, int ops, int mem) =>
      lib.argon2idDerive(passphrase, salt, ops: ops, mem: mem);
}

/// A media file as the key — the same file always yields the same key.
///
/// Uses the DETERMINISTIC entropy path deliberately: `keyFromFile` XORs in
/// fresh system entropy and so could never reopen its own envelope.
final class KeyFileSource extends KeySource with _Builtin {
  const KeyFileSource(this.path);
  final String path;
  @override int get id => 2;
  @override String get label => 'keyFile';
  @override
  Uint8List deriveRoot(CryptoLib lib, Uint8List salt, int ops, int mem) {
    final handle = lib.entropyFromFileDeterministic(path);
    try {
      return lib.entropySymmetricKey(handle);
    } finally {
      lib.entropyFree(handle);
    }
  }
}

/// How a [CryptoRecipe] signs and verifies the plaintext.
///
/// Subclass it for another signature algorithm. A scheme that only holds a
/// public key should throw from [sign]. The signature is always applied to the
/// plaintext BEFORE encryption, so it travels confidentially.
abstract class SignatureScheme {
  const SignatureScheme();

  /// Identifier recorded in the envelope header. Built-ins use 1–2; custom
  /// schemes must use 128–255. Verification requires a scheme with the same id.
  int get id;

  /// Short name for [CryptoRecipe.describe].
  String get label;

  /// Sign [message].
  Uint8List sign(CryptoLib lib, Uint8List message);

  /// Verify [signature] over [message]. Must return false, never throw
  /// through, on a bad signature.
  bool verify(CryptoLib lib, Uint8List message, Uint8List signature);
}

/// Ed25519. Supply [secretKey] to sign, [publicKey] to verify, or both.
final class Ed25519Signature extends SignatureScheme with _Builtin {
  const Ed25519Signature({this.secretKey, this.publicKey});
  final Uint8List? secretKey;
  final Uint8List? publicKey;
  @override int get id => 1;
  @override String get label => 'ed25519';
  @override Uint8List sign(CryptoLib lib, Uint8List m) =>
      lib.ed25519Sign(m, secretKey ?? (throw StateError('cryptolib: Ed25519Signature has no secret key')));
  @override bool verify(CryptoLib lib, Uint8List m, Uint8List sig) =>
      lib.ed25519Verify(m, sig, publicKey ?? (throw StateError('cryptolib: Ed25519Signature has no public key')));
}

/// Ed25519 + ML-DSA-65. A forgery needs breaking both families.
final class HybridSignature extends SignatureScheme with _Builtin {
  const HybridSignature({this.secretKey, this.publicKey});
  final Uint8List? secretKey;
  final Uint8List? publicKey;
  @override int get id => 2;
  @override String get label => 'hybrid';
  @override Uint8List sign(CryptoLib lib, Uint8List m) =>
      lib.hybridSigSign(m, secretKey ?? (throw StateError('cryptolib: HybridSignature has no secret key')));
  @override bool verify(CryptoLib lib, Uint8List m, Uint8List sig) =>
      lib.hybridSigVerify(m, sig, publicKey ?? (throw StateError('cryptolib: HybridSignature has no public key')));
}

/// Built-in signature algorithms, for the [CryptoRecipe.signedBy] shorthand.
enum SignatureAlgorithm {
  /// No signature. The AEAD still guarantees integrity, but not who sent it.
  none(0),

  /// Ed25519.
  ed25519(1),

  /// Ed25519 + ML-DSA-65. A forgery needs breaking both families.
  hybrid(2);

  const SignatureAlgorithm(this.id);

  /// Identifier recorded in the envelope header.
  final int id;
}

/// A composable protection pipeline.
///
/// Describe what you want once, then [seal] and [open] with the same recipe.
/// The envelope carries its own descriptor, so opening does not depend on
/// remembering which layers were used — only on holding the key.
///
/// ```dart
/// final recipe = lib.recipe(SecurityProfile.maximum)
///     .withPassphrase('correct horse battery staple')
///     .signedBy(id.secretKey, algorithm: SignatureAlgorithm.hybrid)
///     .verifiedBy(id.publicKey);
///
/// final envelope = recipe.seal(secret);
/// final back = recipe.open(envelope);
/// ```
///
/// Every part is replaceable with your own subclass — see [ProtectionLayer],
/// [KeySource] and [SignatureScheme]. Builder methods return the same
/// instance, so calls chain.
class CryptoRecipe {
  CryptoRecipe._(this._lib, this.profile) : _layers = List.of(profile.cascade);

  static const List<int> _magic = [0x43, 0x4c, 0x52, 0x43]; // 'CLRC'
  static const List<int> _fecMagic = [0x43, 0x4c, 0x46, 0x43]; // 'CLFC'
  static const int _version = 1;
  static const int _saltLen = 16;

  final CryptoLib _lib;

  /// The profile this recipe started from.
  final SecurityProfile profile;

  List<ProtectionLayer> _layers;
  KeySource? _source;
  SignatureScheme? _signer;
  SignatureScheme? _verifier;
  Uint8List? _verifierKey;
  FecScheme _fec = FecScheme.none;
  int? _argon2Ops;
  int? _argon2Memory;

  // ── Key source (exactly one) ───────────────────────────────────────────────

  /// Use any [KeySource] — a built-in or your own subclass.
  CryptoRecipe withKeySource(KeySource source) {
    _requireValidId(source, source.id, 'key source');
    _source = source;
    return this;
  }

  /// Derive the root key from a passphrase with Argon2id, at this profile's
  /// cost (override with [argon2Cost]). Shorthand for a [PassphraseKeySource].
  CryptoRecipe withPassphrase(String passphrase) => withKeySource(PassphraseKeySource(passphrase));

  /// Use a 32-byte key directly. Shorthand for a [RawKeySource].
  CryptoRecipe withKey(Uint8List key) => withKeySource(RawKeySource(key));

  /// Derive the root key deterministically from a media file. Shorthand for a
  /// [KeyFileSource]. Check the file first with `lib.entropy.assessFileHealth`.
  CryptoRecipe withKeyFile(String path) => withKeySource(KeyFileSource(path));

  // ── Layers ─────────────────────────────────────────────────────────────────

  /// Replace the cascade with exactly these layers, innermost first.
  CryptoRecipe withLayers(List<ProtectionLayer> layers) {
    if (layers.isEmpty) {
      throw ArgumentError.value(layers, 'layers', 'a recipe needs at least one layer');
    }
    for (final l in layers) {
      _requireValidId(l, l.id, 'layer');
    }
    _layers = List.of(layers);
    return this;
  }

  /// Append one more layer on the outside of the current cascade.
  CryptoRecipe addLayer(ProtectionLayer layer) {
    _requireValidId(layer, layer.id, 'layer');
    _layers.add(layer);
    return this;
  }

  /// Override the Argon2id cost. Only meaningful with a passphrase source.
  CryptoRecipe argon2Cost({int? ops, int? memoryBytes}) {
    _argon2Ops = ops;
    _argon2Memory = memoryBytes;
    return this;
  }

  // ── Authenticity ───────────────────────────────────────────────────────────

  /// Sign with any [SignatureScheme] — a built-in or your own subclass.
  CryptoRecipe signedWith(SignatureScheme scheme) {
    _requireValidId(scheme, scheme.id, 'signature scheme');
    _signer = scheme;
    return this;
  }

  /// Verify with any [SignatureScheme]. Required whenever the envelope is
  /// signed: without it there is a signature but nobody checking it, so [open]
  /// refuses rather than silently accepting.
  CryptoRecipe verifiedWith(SignatureScheme scheme) {
    _requireValidId(scheme, scheme.id, 'signature scheme');
    _verifier = scheme;
    _verifierKey = null;
    return this;
  }

  /// Sign the plaintext before it is encrypted, proving who produced it.
  /// Shorthand for [signedWith] with a built-in scheme.
  CryptoRecipe signedBy(Uint8List secretKey,
      {SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519}) {
    final sk = Uint8List.fromList(secretKey);
    return switch (algorithm) {
      SignatureAlgorithm.ed25519 => signedWith(Ed25519Signature(secretKey: sk)),
      SignatureAlgorithm.hybrid => signedWith(HybridSignature(secretKey: sk)),
      SignatureAlgorithm.none =>
        throw ArgumentError.value(algorithm, 'algorithm', 'use signedBy with a real algorithm'),
    };
  }

  /// The public key [open] must verify the embedded signature against.
  ///
  /// Works for either built-in scheme: the envelope records which one it was
  /// signed with, so you need only the key. A custom [SignatureScheme] must be
  /// supplied through [verifiedWith] instead.
  CryptoRecipe verifiedBy(Uint8List publicKey) {
    _verifier = null;
    _verifierKey = Uint8List.fromList(publicKey);
    return this;
  }

  // ── Robustness ─────────────────────────────────────────────────────────────

  /// Apply forward error correction to the finished envelope, so it survives a
  /// carrier that may be recompressed or resampled.
  CryptoRecipe withFec(FecScheme scheme) {
    _fec = scheme;
    return this;
  }

  // ── Seal / open ────────────────────────────────────────────────────────────

  /// Protect [plaintext] and return the envelope.
  Uint8List seal(Uint8List plaintext) {
    final source = _source ??
        (throw StateError('cryptolib: no key set — call withKey/withPassphrase/withKeyFile/withKeySource'));
    final salt = _lib.randomBytes(_saltLen);
    final ops = _argon2Ops ?? profile.argon2Ops;
    final mem = _argon2Memory ?? profile.argon2Memory;
    final header = _buildHeader(source, salt, ops, mem);
    final root = _rootKey(source, salt, ops, mem);

    var body = plaintext;
    final signer = _signer;
    if (signer != null) {
      body = _prefixLengthed(signer.sign(_lib, plaintext), plaintext);
    }

    for (var i = 0; i < _layers.length; i++) {
      body = _applyLayer(_layers[i], i, root, salt, header, body, seal: true);
    }

    final envelope = Uint8List(header.length + body.length)
      ..setAll(0, header)
      ..setAll(header.length, body);
    return _fec == FecScheme.none ? envelope : _wrapFec(envelope);
  }

  /// Recover the plaintext from [envelope]. Throws if the key is wrong, a byte
  /// was altered, or a signature is present but does not verify.
  Uint8List open(Uint8List envelope) {
    final source = _source ??
        (throw StateError('cryptolib: no key set — call withKey/withPassphrase/withKeyFile/withKeySource'));
    final inner = _unwrapFec(envelope);
    final parsed = _parseHeader(inner, source);
    final header = parsed.header;
    final root = _rootKey(source, parsed.salt, parsed.ops, parsed.memory);

    var body = Uint8List.sublistView(inner, header.length);
    for (var i = parsed.layers.length - 1; i >= 0; i--) {
      body = _applyLayer(parsed.layers[i], i, root, parsed.salt, header, body, seal: false);
    }

    if (parsed.signatureId == SignatureAlgorithm.none.id) return body;

    final (sig, plaintext) = _splitLengthed(body);
    final verifier = _verifier ?? _builtinVerifier(parsed.signatureId);
    if (verifier == null) {
      if (_verifierKey != null) {
        // A key alone can only serve a built-in scheme; this envelope names a
        // custom one, which must be supplied as an object.
        throw Exception(
          'cryptolib: envelope was signed with scheme id ${parsed.signatureId}, which is '
          'not a built-in — supply that SignatureScheme with verifiedWith()',
        );
      }
      throw StateError(
        'cryptolib: envelope is signed but no verifier was supplied — '
        'call verifiedBy()/verifiedWith() so the signature is actually checked',
      );
    }
    if (verifier.id != parsed.signatureId) {
      throw Exception(
        'cryptolib: envelope was signed with scheme id ${parsed.signatureId}, '
        'but the verifier is "${verifier.label}" (id ${verifier.id})',
      );
    }
    if (!verifier.verify(_lib, plaintext, sig)) {
      throw Exception('cryptolib: signature verification failed');
    }
    return plaintext;
  }

  /// Seal [plaintext] and hide the envelope inside [coverPath], writing the
  /// result to [outputPath].
  ///
  /// Concealment is defence-in-depth, never the confidentiality boundary — the
  /// envelope is already authenticated-encrypted before it is embedded.
  void sealIntoCarrier(Uint8List plaintext,
      {required String coverPath, required String outputPath}) {
    _lib.stegoEmbed(coverPath, seal(plaintext), outputPath);
  }

  /// Extract and open an envelope previously written by [sealIntoCarrier].
  Uint8List openFromCarrier(String stegoPath) => open(_lib.stegoExtract(stegoPath));

  /// A human-readable summary of what this recipe will do — handy in logs and
  /// code review, where a silently-weak configuration is the thing to catch.
  String describe() {
    final b = StringBuffer('CryptoRecipe(${profile.name})\n')
      ..writeln('  key      : ${_source?.label ?? '(unset)'}')
      ..writeln('  layers   : ${_layers.map((l) => l.wireName).join(' → ')}')
      ..writeln('  signature: ${_signer?.label ?? 'none'}')
      ..writeln('  fec      : ${_fec.name}');
    if (_source is PassphraseKeySource) {
      final mem = (_argon2Memory ?? profile.argon2Memory) ~/ (1024 * 1024);
      b.writeln('  argon2id : ops=${_argon2Ops ?? profile.argon2Ops}, mem=${mem}MiB');
    }
    return b.toString();
  }

  // ── Internals ──────────────────────────────────────────────────────────────

  /// For [verifiedBy]: build the built-in scheme the envelope names, around the
  /// supplied public key. Custom ids resolve to nothing — they need verifiedWith.
  SignatureScheme? _builtinVerifier(int signatureId) {
    final pk = _verifierKey;
    if (pk == null) return null;
    if (signatureId == SignatureAlgorithm.ed25519.id) return Ed25519Signature(publicKey: pk);
    if (signatureId == SignatureAlgorithm.hybrid.id) return HybridSignature(publicKey: pk);
    return null;
  }

  Uint8List _rootKey(KeySource source, Uint8List salt, int ops, int mem) {
    final root = source.deriveRoot(_lib, salt, ops, mem);
    if (root.length != 32) {
      throw StateError(
        'cryptolib: key source "${source.label}" produced ${root.length} bytes; the root key must be exactly 32');
    }
    return root;
  }

  /// Per-layer key: HKDF over the root with a distinct info string, so no two
  /// layers ever share key material.
  Uint8List _layerKey(Uint8List root, Uint8List salt, int index, ProtectionLayer layer) =>
      _lib.hkdfDerive(
        root,
        salt: salt,
        info: Uint8List.fromList('cryptolib/recipe/v1/layer$index/${layer.wireName}'.codeUnits),
      );

  Uint8List _applyLayer(ProtectionLayer layer, int index, Uint8List root, Uint8List salt,
      Uint8List header, Uint8List data, {required bool seal}) {
    final key = _layerKey(root, salt, index, layer);
    return seal ? layer.seal(_lib, key, header, data) : layer.open(_lib, key, header, data);
  }

  Uint8List _buildHeader(KeySource source, Uint8List salt, int ops, int mem) {
    final out = BytesBuilder()
      ..add(_magic)
      ..addByte(_version)
      ..addByte(source.id)
      ..addByte(_signer?.id ?? SignatureAlgorithm.none.id)
      ..addByte(_layers.length);
    for (final l in _layers) {
      out.addByte(l.id);
    }
    out.add(salt);
    final costs = ByteData(8)
      ..setUint32(0, ops)
      ..setUint32(4, mem);
    out.add(costs.buffer.asUint8List());
    return out.toBytes();
  }

  _ParsedHeader _parseHeader(Uint8List env, KeySource source) {
    if (env.length < 8 + _saltLen + 8) throw Exception('cryptolib: envelope too short');
    for (var i = 0; i < 4; i++) {
      if (env[i] != _magic[i]) throw Exception('cryptolib: not a CryptoRecipe envelope');
    }
    if (env[4] != _version) throw Exception('cryptolib: unsupported envelope version ${env[4]}');
    final sourceId = env[5];
    if (sourceId != source.id) {
      throw Exception(
        'cryptolib: envelope was sealed with key source id $sourceId, '
        'but this recipe is configured for "${source.label}" (id ${source.id})',
      );
    }
    final signatureId = env[6];
    final layerCount = env[7];
    final headerLen = 8 + layerCount + _saltLen + 8;
    if (env.length < headerLen) throw Exception('cryptolib: truncated envelope header');
    final layers = [for (var i = 0; i < layerCount; i++) ProtectionLayer._resolve(env[8 + i])];
    final salt = Uint8List.fromList(env.sublist(8 + layerCount, 8 + layerCount + _saltLen));
    final costs = ByteData.sublistView(env, 8 + layerCount + _saltLen, headerLen);
    return _ParsedHeader(
      header: Uint8List.fromList(env.sublist(0, headerLen)),
      layers: layers,
      salt: salt,
      signatureId: signatureId,
      ops: costs.getUint32(0),
      memory: costs.getUint32(4),
    );
  }

  Uint8List _wrapFec(Uint8List envelope) {
    final encoded = _lib.fecEncode(envelope, _fec);
    final out = BytesBuilder()
      ..add(_fecMagic)
      ..addByte(_fec.value);
    final len = ByteData(4)..setUint32(0, envelope.length);
    out
      ..add(len.buffer.asUint8List())
      ..add(encoded);
    return out.toBytes();
  }

  Uint8List _unwrapFec(Uint8List data) {
    if (data.length < 9) return data;
    for (var i = 0; i < 4; i++) {
      if (data[i] != _fecMagic[i]) return data;
    }
    final scheme = FecScheme.values.firstWhere((s) => s.value == data[4],
        orElse: () => throw Exception('cryptolib: unknown FEC scheme ${data[4]}'));
    final originalLen = ByteData.sublistView(data, 5, 9).getUint32(0);
    return _lib.fecDecode(Uint8List.sublistView(data, 9), scheme, originalLen);
  }

  static Uint8List _prefixLengthed(Uint8List prefix, Uint8List rest) {
    final len = ByteData(4)..setUint32(0, prefix.length);
    return (BytesBuilder()
          ..add(len.buffer.asUint8List())
          ..add(prefix)
          ..add(rest))
        .toBytes();
  }

  static (Uint8List, Uint8List) _splitLengthed(Uint8List data) {
    if (data.length < 4) throw Exception('cryptolib: malformed signed payload');
    final n = ByteData.sublistView(data, 0, 4).getUint32(0);
    if (data.length < 4 + n) throw Exception('cryptolib: malformed signed payload');
    return (
      Uint8List.fromList(data.sublist(4, 4 + n)),
      Uint8List.fromList(data.sublist(4 + n)),
    );
  }
}

class _ParsedHeader {
  const _ParsedHeader({
    required this.header,
    required this.layers,
    required this.salt,
    required this.signatureId,
    required this.ops,
    required this.memory,
  });

  final Uint8List header;
  final List<ProtectionLayer> layers;
  final Uint8List salt;
  final int signatureId;
  final int ops;
  final int memory;
}

/// Profile-driven entry points.
extension CryptoLibSecurity on CryptoLib {
  /// Start a [CryptoRecipe] at the given profile's settings.
  ///
  /// The profile only sets defaults — every part stays overridable.
  CryptoRecipe recipe([SecurityProfile profile = SecurityProfile.balanced]) =>
      CryptoRecipe._(this, profile);

  /// A recipe using the strongest option at every choice. Shorthand for
  /// `recipe(SecurityProfile.maximum)`.
  CryptoRecipe maximumSecurity() => CryptoRecipe._(this, SecurityProfile.maximum);
}
