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

/// One authenticated-encryption layer in a [CryptoRecipe] cascade.
enum ProtectionLayer {
  /// XChaCha20-Poly1305. Large nonce, no timing-sensitive tables.
  xchacha20Poly1305(1),

  /// AES-256-GCM. A different cipher family from ChaCha.
  aes256Gcm(2),

  /// Key-committing AEAD (UtC). Binds the ciphertext to exactly one key.
  committing(3),

  /// A full MolecularVault (cascade + committing) nested as one layer.
  molecular(4);

  const ProtectionLayer(this.id);

  /// Identifier recorded in the envelope header.
  final int id;

  static ProtectionLayer _fromId(int id) =>
      ProtectionLayer.values.firstWhere((l) => l.id == id,
          orElse: () => throw Exception('cryptolib: unknown protection layer id $id'));
}

/// Origin-authentication algorithm for a [CryptoRecipe].
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

  static SignatureAlgorithm _fromId(int id) =>
      SignatureAlgorithm.values.firstWhere((s) => s.id == id,
          orElse: () => throw Exception('cryptolib: unknown signature id $id'));
}

enum _KeySource {
  raw(0),
  passphrase(1),
  keyFile(2);

  const _KeySource(this.id);
  final int id;

  static _KeySource _fromId(int id) => _KeySource.values.firstWhere((k) => k.id == id,
      orElse: () => throw Exception('cryptolib: unknown key source id $id'));
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
/// Every builder method returns the same instance, so calls chain.
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
  _KeySource _source = _KeySource.raw;
  Uint8List? _rawKey;
  String? _passphrase;
  String? _keyFilePath;
  SignatureAlgorithm _signAlgorithm = SignatureAlgorithm.none;
  Uint8List? _signingSecret;
  Uint8List? _signingPublic;
  FecScheme _fec = FecScheme.none;
  int? _argon2Ops;
  int? _argon2Memory;

  // ── Key source (exactly one) ───────────────────────────────────────────────

  /// Derive the root key from a passphrase with Argon2id, at this profile's
  /// cost (override with [argon2Cost]).
  CryptoRecipe withPassphrase(String passphrase) {
    _source = _KeySource.passphrase;
    _passphrase = passphrase;
    return this;
  }

  /// Use a 32-byte key directly — from a KEM shared secret, a keyring unlock, a
  /// hardware token, anywhere. Nothing is stretched; the key must already be
  /// full-entropy.
  CryptoRecipe withKey(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, 'key.length', 'root key must be exactly 32 bytes');
    }
    _source = _KeySource.raw;
    _rawKey = Uint8List.fromList(key);
    return this;
  }

  /// Derive the root key deterministically from a media file — "the file is the
  /// key". The same file always yields the same key on any machine, and nothing
  /// is stored.
  ///
  /// This uses the reproducible entropy path deliberately. `keyFromFile` mixes
  /// in fresh system entropy and so cannot reopen its own envelope.
  ///
  /// Check the file first with `lib.entropy.assessFileHealth`: a low-entropy
  /// carrier makes a weak key no matter how many layers sit on top.
  CryptoRecipe withKeyFile(String path) {
    _source = _KeySource.keyFile;
    _keyFilePath = path;
    return this;
  }

  // ── Layers ─────────────────────────────────────────────────────────────────

  /// Replace the cascade with exactly these layers, innermost first.
  CryptoRecipe withLayers(List<ProtectionLayer> layers) {
    if (layers.isEmpty) {
      throw ArgumentError.value(layers, 'layers', 'a recipe needs at least one layer');
    }
    _layers = List.of(layers);
    return this;
  }

  /// Append one more layer on the outside of the current cascade.
  CryptoRecipe addLayer(ProtectionLayer layer) {
    _layers.add(layer);
    return this;
  }

  /// Override the Argon2id cost. Only meaningful with [withPassphrase].
  CryptoRecipe argon2Cost({int? ops, int? memoryBytes}) {
    _argon2Ops = ops;
    _argon2Memory = memoryBytes;
    return this;
  }

  // ── Authenticity ───────────────────────────────────────────────────────────

  /// Sign the plaintext before it is encrypted, proving who produced it.
  ///
  /// The signature travels inside the encryption, so it reveals nothing about
  /// the sender to an observer.
  CryptoRecipe signedBy(Uint8List secretKey,
      {SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519}) {
    if (algorithm == SignatureAlgorithm.none) {
      throw ArgumentError.value(algorithm, 'algorithm', 'use signedBy with a real algorithm');
    }
    _signAlgorithm = algorithm;
    _signingSecret = Uint8List.fromList(secretKey);
    return this;
  }

  /// The public key [open] must verify the embedded signature against.
  ///
  /// Required whenever the envelope is signed: without it there is a signature
  /// but nobody checking it, so [open] refuses rather than silently accepting.
  CryptoRecipe verifiedBy(Uint8List publicKey) {
    _signingPublic = Uint8List.fromList(publicKey);
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
    final salt = _lib.randomBytes(_saltLen);
    final ops = _argon2Ops ?? profile.argon2Ops;
    final mem = _argon2Memory ?? profile.argon2Memory;
    final header = _buildHeader(salt, ops, mem);
    final root = _rootKey(salt, ops, mem);

    var body = plaintext;
    if (_signAlgorithm != SignatureAlgorithm.none) {
      final secret = _signingSecret;
      if (secret == null) throw StateError('cryptolib: signing requested without a secret key');
      final sig = switch (_signAlgorithm) {
        SignatureAlgorithm.ed25519 => _lib.ed25519Sign(plaintext, secret),
        SignatureAlgorithm.hybrid => _lib.hybridSigSign(plaintext, secret),
        SignatureAlgorithm.none => Uint8List(0),
      };
      body = _prefixLengthed(sig, plaintext);
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
    final inner = _unwrapFec(envelope);
    final parsed = _parseHeader(inner);
    final header = parsed.header;
    final root = _rootKey(parsed.salt, parsed.ops, parsed.memory);

    var body = Uint8List.sublistView(inner, header.length);
    for (var i = parsed.layers.length - 1; i >= 0; i--) {
      body = _applyLayer(parsed.layers[i], i, root, parsed.salt, header, body, seal: false);
    }

    if (parsed.signAlgorithm == SignatureAlgorithm.none) return body;

    final (sig, plaintext) = _splitLengthed(body);
    final pub = _signingPublic;
    if (pub == null) {
      throw StateError(
        'cryptolib: envelope is signed but no public key was supplied — '
        'call verifiedBy() so the signature is actually checked',
      );
    }
    final ok = switch (parsed.signAlgorithm) {
      SignatureAlgorithm.ed25519 => _lib.ed25519Verify(plaintext, sig, pub),
      SignatureAlgorithm.hybrid => _lib.hybridSigVerify(plaintext, sig, pub),
      SignatureAlgorithm.none => false,
    };
    if (!ok) throw Exception('cryptolib: signature verification failed');
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
      ..writeln('  key      : ${_source.name}')
      ..writeln('  layers   : ${_layers.map((l) => l.name).join(' → ')}')
      ..writeln('  signature: ${_signAlgorithm.name}')
      ..writeln('  fec      : ${_fec.name}');
    if (_source == _KeySource.passphrase) {
      final mem = (_argon2Memory ?? profile.argon2Memory) ~/ (1024 * 1024);
      b.writeln('  argon2id : ops=${_argon2Ops ?? profile.argon2Ops}, mem=${mem}MiB');
    }
    return b.toString();
  }

  // ── Internals ──────────────────────────────────────────────────────────────

  Uint8List _rootKey(Uint8List salt, int ops, int mem) => switch (_source) {
        _KeySource.raw => _rawKey ??
            (throw StateError('cryptolib: no key set — call withKey/withPassphrase/withKeyFile')),
        _KeySource.passphrase => _lib.argon2idDerive(
            _passphrase ?? (throw StateError('cryptolib: no passphrase set')),
            salt,
            ops: ops,
            mem: mem,
          ),
        // Must be the DETERMINISTIC path: keyFromFile XORs in fresh system
        // entropy, so it returns a different key on every call and could never
        // reopen its own envelope.
        _KeySource.keyFile => _deterministicFileKey(
            _keyFilePath ?? (throw StateError('cryptolib: no key file set')),
          ),
      };

  Uint8List _deterministicFileKey(String path) {
    final handle = _lib.entropyFromFileDeterministic(path);
    try {
      return _lib.entropySymmetricKey(handle);
    } finally {
      _lib.entropyFree(handle);
    }
  }

  /// Per-layer key: HKDF over the root with a distinct info string, so no two
  /// layers ever share key material.
  Uint8List _layerKey(Uint8List root, Uint8List salt, int index, ProtectionLayer layer) =>
      _lib.hkdfDerive(
        root,
        salt: salt,
        info: Uint8List.fromList('cryptolib/recipe/v1/layer$index/${layer.name}'.codeUnits),
      );

  Uint8List _applyLayer(ProtectionLayer layer, int index, Uint8List root, Uint8List salt,
      Uint8List header, Uint8List data, {required bool seal}) {
    final key = _layerKey(root, salt, index, layer);
    return switch (layer) {
      ProtectionLayer.xchacha20Poly1305 =>
        seal ? _lib.xchacha20Encrypt(data, key, header) : _lib.xchacha20Decrypt(data, key, header),
      ProtectionLayer.aes256Gcm =>
        seal ? _lib.aes256gcmEncrypt(data, key, header) : _lib.aes256gcmDecrypt(data, key, header),
      ProtectionLayer.committing =>
        seal ? _lib.committingEncrypt(data, key, header) : _lib.committingDecrypt(data, key, header),
      ProtectionLayer.molecular => seal
          ? _lib.molecularSealWithKey(data, key, aad: header)
          : _lib.molecularOpenWithKey(data, key, aad: header),
    };
  }

  Uint8List _buildHeader(Uint8List salt, int ops, int mem) {
    final out = BytesBuilder()
      ..add(_magic)
      ..addByte(_version)
      ..addByte(_source.id)
      ..addByte(_signAlgorithm.id)
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

  _ParsedHeader _parseHeader(Uint8List env) {
    if (env.length < 8 + _saltLen + 8) throw Exception('cryptolib: envelope too short');
    for (var i = 0; i < 4; i++) {
      if (env[i] != _magic[i]) throw Exception('cryptolib: not a CryptoRecipe envelope');
    }
    if (env[4] != _version) throw Exception('cryptolib: unsupported envelope version ${env[4]}');
    final source = _KeySource._fromId(env[5]);
    if (source != _source) {
      throw Exception(
        'cryptolib: envelope was sealed with the ${source.name} key source, '
        'but this recipe is configured for ${_source.name}',
      );
    }
    final signAlgorithm = SignatureAlgorithm._fromId(env[6]);
    final layerCount = env[7];
    final headerLen = 8 + layerCount + _saltLen + 8;
    if (env.length < headerLen) throw Exception('cryptolib: truncated envelope header');
    final layers = [for (var i = 0; i < layerCount; i++) ProtectionLayer._fromId(env[8 + i])];
    final salt = Uint8List.fromList(env.sublist(8 + layerCount, 8 + layerCount + _saltLen));
    final costs = ByteData.sublistView(env, 8 + layerCount + _saltLen, headerLen);
    return _ParsedHeader(
      header: Uint8List.fromList(env.sublist(0, headerLen)),
      layers: layers,
      salt: salt,
      signAlgorithm: signAlgorithm,
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
    required this.signAlgorithm,
    required this.ops,
    required this.memory,
  });

  final Uint8List header;
  final List<ProtectionLayer> layers;
  final Uint8List salt;
  final SignatureAlgorithm signAlgorithm;
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
