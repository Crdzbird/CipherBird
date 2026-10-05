part of '../cipher_bird.dart';

/// The easy-mode entry points, reachable as `lib.easy`.
extension type EasyApi(CipherBird _l) {
  /// A fresh [SymmetricKey].
  SymmetricKey symmetricKey() => SymmetricKey.generate(_l);

  /// A [SymmetricKey] stretched from a passphrase; see [SymmetricKey.fromPassphrase].
  SymmetricKey symmetricKeyFromPassphrase(
    String passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
  }) => SymmetricKey.fromPassphrase(
    passphrase,
    salt: salt,
    profile: profile,
    lib: _l,
  );

  /// A fresh [SigningKey].
  SigningKey signingKey({
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
  }) => SigningKey.generate(algorithm: algorithm, lib: _l);

  /// A fresh [KemKeyPair].
  KemKeyPair kemKeyPair() => KemKeyPair.generate(_l);

  /// A fresh sealed-messaging [Identity] (Flagship by default, Fortress for the
  /// strongest tier).
  Identity identity([SealedTier tier = SealedTier.flagship]) =>
      _l.newIdentity(tier);

  /// [n] random bytes from the OS CSPRNG.
  Uint8List randomBytes(int n) => _l.randomBytes(n);

  /// [bytes] random bytes as lowercase hex.
  String randomHex(int bytes) => toHex(_l.randomBytes(bytes));

  /// An opaque URL-safe random token (session ids, nonces); [bytes] of entropy.
  String token([int bytes = 32]) => _l.randomBytes(bytes).base64Url;

  /// Hash a password for storage (Argon2id, PHC string). Store the result;
  /// check it later with [verifyPassword]. Cost comes from [profile].
  String hashPassword(
    String password, {
    SecurityProfile profile = SecurityProfile.balanced,
  }) {
    final raw = _l.argon2idHashStr(
      password,
      ops: profile.argon2Ops,
      mem: profile.argon2Memory,
    );
    final end = raw.indexOf(0);
    return utf8.decode(end < 0 ? raw : Uint8List.sublistView(raw, 0, end));
  }

  /// True if [password] matches a PHC string from [hashPassword].
  bool verifyPassword(String password, String phcHash) =>
      _l.argon2idVerifyStr(password, phcHash);

  /// SHA-256 of a string, as hex. For anything security-sensitive prefer
  /// [SigningKey] or a MAC - a bare hash proves nothing about who made it.
  String sha256Hex(String text) => toHex(_l.sha256(text.bytes));
}
