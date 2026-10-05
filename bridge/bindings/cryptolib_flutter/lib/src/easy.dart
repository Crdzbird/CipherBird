part of 'cryptolib.dart';

// ═══ Easy mode ════════════════════════════════════════════════════════════════
//
// The raw API is byte-oriented and exhaustive (~265 operations) — exactly what a
// binding should be, and exactly what an app developer does not want to think
// about on a Tuesday. This file adds two things on top, without changing or
// hiding anything underneath:
//
//   1. Bytes/text sugar — `'hello'.bytes`, `digest.hex`, `'ab12'.hexBytes`,
//      `blob.base64`, `a.constantTimeEquals(b)` — so Uint8List plumbing stops
//      being most of the code.
//   2. Small classes that bundle a key with the right algorithm and the safe
//      defaults: [SymmetricKey] (key-committing AEAD, Argon2id for passphrases,
//      HKDF sub-keys), [SigningKey]/[VerifyKey] (Ed25519 or the PQ hybrid),
//      [KemKeyPair] (hybrid X25519+ML-KEM-768 key agreement, one-call
//      public-key encryption), and `lib.easy` for passwords and randomness.
//
// Every class takes an optional [CryptoLib]; it defaults to [CryptoLib.instance]
// so the common case is `SymmetricKey.generate()`. Composition only — nothing
// here is new cryptography, and every class exposes its raw bytes so you can
// drop back to the full API at any point.

CryptoLib _easyLib(CryptoLib? lib) => lib ?? CryptoLib.instance;

// ── Bytes & text ─────────────────────────────────────────────────────────────

/// Text → bytes conversions. `'hello'.bytes`, `'ab12'.hexBytes`, `'aGk='.base64Bytes`.
extension CryptoText on String {
  /// UTF-8 bytes of this string.
  Uint8List get bytes => Uint8List.fromList(utf8.encode(this));

  /// Decode this hex string (case-insensitive, no `0x`) into bytes.
  Uint8List get hexBytes => fromHex(this);

  /// Decode this base64 (standard or URL-safe) string into bytes.
  Uint8List get base64Bytes => base64Decode(base64.normalize(this));
}

/// Bytes → text conversions and the two byte helpers every app ends up writing.
extension CryptoBytes on Uint8List {
  /// Lowercase hex, no prefix.
  String get hex => toHex(this);

  /// Standard base64 (with padding).
  String get base64 => base64Encode(this);

  /// URL-safe base64 without padding — safe in URLs, file names and JSON.
  String get base64Url => base64UrlEncode(this).replaceAll('=', '');

  /// Decode as UTF-8 text. Throws on invalid UTF-8.
  String get text => utf8.decode(this);

  /// Compare in constant time. Use this for tags, MACs and tokens — a plain
  /// `==` / `listEquals` leaks where the first mismatch is.
  bool constantTimeEquals(List<int> other) {
    if (length != other.length) return false;
    var diff = 0;
    for (var i = 0; i < length; i++) {
      diff |= this[i] ^ other[i];
    }
    return diff == 0;
  }

  /// A new buffer holding `this` followed by [other].
  Uint8List concat(List<int> other) => Uint8List(length + other.length)
    ..setRange(0, length, this)
    ..setRange(length, length + other.length, other);

  /// Overwrite with zeros. Call on key material you are done with.
  void wipe() => fillRange(0, length, 0);
}

/// `List<int>` → `Uint8List` without copying when it already is one.
extension CryptoByteList on List<int> {
  /// This list as a [Uint8List] (no copy if it already is one).
  Uint8List get u8 => this is Uint8List ? this as Uint8List : Uint8List.fromList(this);
}

/// Hex views of a raw key pair.
extension KeyPairText on KeyPairResult {
  /// Public key as lowercase hex.
  String get publicHex => toHex(publicKey);

  /// Secret key as lowercase hex. Handle with care.
  String get secretHex => toHex(secretKey);
}

// ── Symmetric ────────────────────────────────────────────────────────────────

/// A 32-byte symmetric key with the safe choices built in.
///
/// Encryption is the **key-committing** AEAD (a ciphertext can only ever open
/// under the one key that made it — no partitioning-oracle or "invisible
/// salamander" attacks). Passphrases are stretched with Argon2id at a
/// [SecurityProfile] cost. Sub-keys come from HKDF, so one key can safely serve
/// several purposes.
///
/// ```dart
/// final key = SymmetricKey.generate();
/// final box = key.encryptText('meet at dawn');      // base64 string
/// final back = key.decryptText(box);                // 'meet at dawn'
///
/// final salt = CryptoLib.instance.easy.randomBytes(16); // store it next to the data
/// final pk = SymmetricKey.fromPassphrase('correct horse battery staple', salt: salt);
/// ```
final class SymmetricKey {
  SymmetricKey._(this._lib, this._key);

  /// A fresh random key.
  factory SymmetricKey.generate([CryptoLib? lib]) {
    final l = _easyLib(lib);
    return SymmetricKey._(l, l.randomBytes(32));
  }

  /// Wrap existing 32-byte key material (a KEM shared secret, a keyring
  /// unlock, a token). Copies the bytes.
  factory SymmetricKey.fromBytes(List<int> key, [CryptoLib? lib]) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, 'key', 'a SymmetricKey is exactly 32 bytes');
    }
    return SymmetricKey._(_easyLib(lib), Uint8List.fromList(key));
  }

  /// From a hex string produced by [hex].
  factory SymmetricKey.fromHex(String hex, [CryptoLib? lib]) => SymmetricKey.fromBytes(fromHex(hex), lib);

  /// From a base64 string produced by [base64].
  factory SymmetricKey.fromBase64(String base64, [CryptoLib? lib]) =>
      SymmetricKey.fromBytes(base64.base64Bytes, lib);

  /// Stretch a passphrase with Argon2id. [salt] must be at least 16 random
  /// bytes and must be stored next to the ciphertext (it is not secret). The
  /// same passphrase + salt always yields the same key. Cost comes from
  /// [profile] (balanced ≈ 64 MiB, 2 passes) unless [ops]/[memoryBytes]
  /// override it.
  factory SymmetricKey.fromPassphrase(
    String passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
    int? ops,
    int? memoryBytes,
    CryptoLib? lib,
  }) {
    if (salt.length < 16) {
      throw ArgumentError.value(salt.length, 'salt', 'use at least 16 random bytes');
    }
    final l = _easyLib(lib);
    return SymmetricKey._(
      l,
      l.argon2idDerive(passphrase, salt, ops: ops ?? profile.argon2Ops, mem: memoryBytes ?? profile.argon2Memory),
    );
  }

  final CryptoLib _lib;
  final Uint8List _key;

  /// A copy of the raw key bytes.
  Uint8List get bytes => Uint8List.fromList(_key);

  /// The key as lowercase hex.
  String get hex => toHex(_key);

  /// The key as base64.
  String get base64 => base64Encode(_key);

  /// An independent sub-key for [purpose] (HKDF). Same key + same purpose →
  /// same sub-key; different purposes never collide. Use it to give each
  /// feature of your app its own key from one root.
  SymmetricKey derive(String purpose) =>
      SymmetricKey._(_lib, _lib.hkdfDerive(_key, info: purpose.bytes));

  /// Encrypt with the key-committing AEAD. [aad] is authenticated but not
  /// encrypted (a header, an id — anything that must match on decrypt).
  Uint8List encrypt(List<int> plaintext, {List<int>? aad}) =>
      _lib.committingEncrypt(plaintext.u8, _key, aad?.u8);

  /// Decrypt. Throws if the key, the data or [aad] do not match.
  Uint8List decrypt(List<int> ciphertext, {List<int>? aad}) =>
      _lib.committingDecrypt(ciphertext.u8, _key, aad?.u8);

  /// Encrypt a string; returns base64 you can store or send as text.
  String encryptText(String plaintext, {String? aad}) => encrypt(plaintext.bytes, aad: aad?.bytes).base64;

  /// Decrypt a string made by [encryptText].
  String decryptText(String ciphertextBase64, {String? aad}) =>
      decrypt(ciphertextBase64.base64Bytes, aad: aad?.bytes).text;

  /// Use this key as a [CryptoRecipe] key source: `lib.recipe().withKeySource(key.asKeySource)`.
  KeySource get asKeySource => RawKeySource(_key);

  /// Zero the key bytes. The object is unusable afterwards.
  void destroy() => _key.wipe();
}

// ── Signatures ───────────────────────────────────────────────────────────────

/// A signing key pair: Ed25519 by default, or the post-quantum hybrid
/// (Ed25519 + ML-DSA-65, a forgery needs breaking both).
///
/// ```dart
/// final key = SigningKey.generate();
/// final sig = key.signText('release 4.1.0');
/// final ok = key.verifyKey.verifyText('release 4.1.0', sig);
/// ```
final class SigningKey {
  SigningKey._(this._lib, this.algorithm, this._pair);

  /// A fresh key pair.
  factory SigningKey.generate({SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519, CryptoLib? lib}) {
    final l = _easyLib(lib);
    return SigningKey._(l, algorithm, switch (algorithm) {
      SignatureAlgorithm.ed25519 => l.ed25519Keygen(),
      SignatureAlgorithm.hybrid => l.hybridSigKeygen(),
      SignatureAlgorithm.none => throw ArgumentError.value(algorithm, 'algorithm', 'pick a real algorithm'),
    });
  }

  /// Wrap existing key bytes (e.g. loaded from secure storage).
  factory SigningKey.fromBytes({
    required List<int> secretKey,
    required List<int> publicKey,
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
    CryptoLib? lib,
  }) =>
      SigningKey._(
        _easyLib(lib),
        algorithm,
        KeyPairResult(publicKey: publicKey.u8, secretKey: secretKey.u8),
      );

  final CryptoLib _lib;

  /// Which scheme this key belongs to.
  final SignatureAlgorithm algorithm;
  final KeyPairResult _pair;

  /// Public key bytes — share freely.
  Uint8List get publicKey => _pair.publicKey;

  /// Secret key bytes — never leave the device.
  Uint8List get secretKey => _pair.secretKey;

  /// The verification half, safe to hand to anyone.
  VerifyKey get verifyKey => VerifyKey.fromBytes(publicKey, algorithm: algorithm, lib: _lib);

  /// Sign [message]; returns the detached signature.
  Uint8List sign(List<int> message) => switch (algorithm) {
        SignatureAlgorithm.hybrid => _lib.hybridSigSign(message.u8, secretKey),
        _ => _lib.ed25519Sign(message.u8, secretKey),
      };

  /// Sign a string; returns the signature as base64.
  String signText(String message) => sign(message.bytes).base64;

  /// Verify with this key's own public half.
  bool verify(List<int> message, List<int> signature) => verifyKey.verify(message, signature);

  /// Plug into a [CryptoRecipe]: `recipe.signedWith(key.scheme)`.
  SignatureScheme get scheme {
    if (algorithm == SignatureAlgorithm.hybrid) {
      return HybridSignature(secretKey: secretKey, publicKey: publicKey);
    }
    return Ed25519Signature(secretKey: secretKey, publicKey: publicKey);
  }
}

/// The public half of a [SigningKey].
final class VerifyKey {
  VerifyKey._(this._lib, this.algorithm, this.publicKey);

  /// From public key bytes.
  factory VerifyKey.fromBytes(List<int> publicKey,
          {SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519, CryptoLib? lib}) =>
      VerifyKey._(_easyLib(lib), algorithm, publicKey.u8);

  /// From a hex public key.
  factory VerifyKey.fromHex(String publicKeyHex,
          {SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519, CryptoLib? lib}) =>
      VerifyKey.fromBytes(fromHex(publicKeyHex), algorithm: algorithm, lib: lib);

  final CryptoLib _lib;

  /// Which scheme this key belongs to.
  final SignatureAlgorithm algorithm;

  /// Public key bytes.
  final Uint8List publicKey;

  /// True if [signature] is a valid signature of [message] under this key.
  bool verify(List<int> message, List<int> signature) => switch (algorithm) {
        SignatureAlgorithm.hybrid => _lib.hybridSigVerify(message.u8, signature.u8, publicKey),
        _ => _lib.ed25519Verify(message.u8, signature.u8, publicKey),
      };

  /// Verify a string against a base64 signature from [SigningKey.signText].
  bool verifyText(String message, String signatureBase64) => verify(message.bytes, signatureBase64.base64Bytes);

  /// Plug into a [CryptoRecipe]: `recipe.verifiedWith(key.scheme)`.
  SignatureScheme get scheme {
    if (algorithm == SignatureAlgorithm.hybrid) return HybridSignature(publicKey: publicKey);
    return Ed25519Signature(publicKey: publicKey);
  }
}

// ── Public-key encryption (post-quantum hybrid KEM) ──────────────────────────

/// A hybrid X25519 + ML-KEM-768 key pair: a shared key that stays secret if
/// *either* half holds (harvest-now-decrypt-later resistant).
///
/// Two ways to use it:
///
/// ```dart
/// // One call each way — encrypt to someone's public key, no session needed.
/// final me = KemKeyPair.generate();
/// final blob = KemKeyPair.encryptFor(me.publicKey, 'hello'.bytes);
/// final back = me.decrypt(blob);
///
/// // Or just agree on a SymmetricKey and keep using it.
/// final (ciphertext, key) = KemKeyPair.encapsulate(me.publicKey);
/// final sameKey = me.decapsulate(ciphertext);
/// ```
final class KemKeyPair {
  KemKeyPair._(this._lib, this._pair);

  /// A fresh key pair.
  factory KemKeyPair.generate([CryptoLib? lib]) {
    final l = _easyLib(lib);
    return KemKeyPair._(l, l.hybridKemKeygen());
  }

  /// Wrap existing key bytes.
  factory KemKeyPair.fromBytes({required List<int> publicKey, required List<int> secretKey, CryptoLib? lib}) =>
      KemKeyPair._(_easyLib(lib), KeyPairResult(publicKey: publicKey.u8, secretKey: secretKey.u8));

  static const _info = 'cryptolib/easy/kem/v1';

  final CryptoLib _lib;
  final KeyPairResult _pair;

  /// Public key bytes — share freely.
  Uint8List get publicKey => _pair.publicKey;

  /// Secret key bytes — never leave the device.
  Uint8List get secretKey => _pair.secretKey;

  /// Sender side: agree on a key with the owner of [recipientPublicKey].
  /// Send the ciphertext; keep the key.
  static (Uint8List ciphertext, SymmetricKey key) encapsulate(List<int> recipientPublicKey, [CryptoLib? lib]) {
    final l = _easyLib(lib);
    final (ct, ss) = l.hybridKemEncapsulate(recipientPublicKey.u8);
    return (ct, SymmetricKey._(l, l.hkdfDerive(ss, info: _info.bytes)));
  }

  /// Recipient side: recover the key agreed in [encapsulate].
  SymmetricKey decapsulate(List<int> ciphertext) => SymmetricKey._(
        _lib,
        _lib.hkdfDerive(_lib.hybridKemDecapsulate(ciphertext.u8, secretKey), info: _info.bytes),
      );

  /// One-call public-key encryption: a self-contained blob only the owner of
  /// [recipientPublicKey] can open with [decrypt]. The blob is the KEM
  /// ciphertext followed by a key-committing AEAD of [plaintext]; [aad] is
  /// authenticated and must be repeated on [decrypt].
  static Uint8List encryptFor(List<int> recipientPublicKey, List<int> plaintext, {List<int>? aad, CryptoLib? lib}) {
    final (ct, key) = encapsulate(recipientPublicKey, lib);
    final body = key.encrypt(plaintext, aad: aad);
    final out = Uint8List(4 + ct.length + body.length);
    ByteData.sublistView(out).setUint32(0, ct.length);
    out
      ..setRange(4, 4 + ct.length, ct)
      ..setRange(4 + ct.length, out.length, body);
    return out;
  }

  /// Open a blob made by [encryptFor] for this key pair.
  Uint8List decrypt(List<int> blob, {List<int>? aad}) {
    final b = blob.u8;
    if (b.length < 4) throw ArgumentError('cryptolib: malformed blob');
    final n = ByteData.sublistView(b).getUint32(0);
    if (b.length < 4 + n) throw ArgumentError('cryptolib: malformed blob');
    return decapsulate(Uint8List.sublistView(b, 4, 4 + n)).decrypt(Uint8List.sublistView(b, 4 + n), aad: aad);
  }

  /// [encryptFor] for strings; returns base64.
  static String encryptTextFor(List<int> recipientPublicKey, String plaintext, {String? aad, CryptoLib? lib}) =>
      encryptFor(recipientPublicKey, plaintext.bytes, aad: aad?.bytes, lib: lib).base64;

  /// [decrypt] for strings made by [encryptTextFor].
  String decryptText(String blobBase64, {String? aad}) => decrypt(blobBase64.base64Bytes, aad: aad?.bytes).text;
}

// ── Sealed messaging text sugar ──────────────────────────────────────────────

/// String convenience on the Flagship/Fortress [Identity].
extension IdentityText on Identity {
  /// Seal a string for the holder of [to]; returns base64.
  String sealText(String plaintext, {required Uint8List to, String? aad, String? purpose}) =>
      seal(plaintext.bytes, to, aad: aad?.bytes, purpose: purpose?.bytes).base64;

  /// Open a base64 envelope from the holder of [from].
  String openText(String envelopeBase64, {required Uint8List from, String? aad, String? purpose}) =>
      open(envelopeBase64.base64Bytes, from, aad: aad?.bytes, purpose: purpose?.bytes).text;
}

// ── lib.easy ─────────────────────────────────────────────────────────────────

/// The easy-mode entry points, reachable as `lib.easy`.
extension type EasyApi(CryptoLib _l) {
  /// A fresh [SymmetricKey].
  SymmetricKey symmetricKey() => SymmetricKey.generate(_l);

  /// A [SymmetricKey] stretched from a passphrase; see [SymmetricKey.fromPassphrase].
  SymmetricKey symmetricKeyFromPassphrase(String passphrase,
          {required Uint8List salt, SecurityProfile profile = SecurityProfile.balanced}) =>
      SymmetricKey.fromPassphrase(passphrase, salt: salt, profile: profile, lib: _l);

  /// A fresh [SigningKey].
  SigningKey signingKey({SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519}) =>
      SigningKey.generate(algorithm: algorithm, lib: _l);

  /// A fresh [KemKeyPair].
  KemKeyPair kemKeyPair() => KemKeyPair.generate(_l);

  /// A fresh sealed-messaging [Identity] (Flagship by default, Fortress for the
  /// strongest tier).
  Identity identity([SealedTier tier = SealedTier.flagship]) => _l.newIdentity(tier);

  /// [n] random bytes from the OS CSPRNG.
  Uint8List randomBytes(int n) => _l.randomBytes(n);

  /// [bytes] random bytes as lowercase hex.
  String randomHex(int bytes) => toHex(_l.randomBytes(bytes));

  /// An opaque URL-safe random token (session ids, nonces); [bytes] of entropy.
  String token([int bytes = 32]) => _l.randomBytes(bytes).base64Url;

  /// Hash a password for storage (Argon2id, PHC string). Store the result;
  /// check it later with [verifyPassword]. Cost comes from [profile].
  String hashPassword(String password, {SecurityProfile profile = SecurityProfile.balanced}) {
    final raw = _l.argon2idHashStr(password, ops: profile.argon2Ops, mem: profile.argon2Memory);
    final end = raw.indexOf(0);
    return utf8.decode(end < 0 ? raw : Uint8List.sublistView(raw, 0, end));
  }

  /// True if [password] matches a PHC string from [hashPassword].
  bool verifyPassword(String password, String phcHash) => _l.argon2idVerifyStr(password, phcHash);

  /// SHA-256 of a string, as hex. For anything security-sensitive prefer
  /// [SigningKey] or a MAC — a bare hash proves nothing about who made it.
  String sha256Hex(String text) => toHex(_l.sha256(text.bytes));
}

/// `lib.easy` — the easy-mode entry points.
extension CryptoLibEasy on CryptoLib {
  /// Keys and helpers with the safe defaults built in.
  EasyApi get easy => EasyApi(this);
}
