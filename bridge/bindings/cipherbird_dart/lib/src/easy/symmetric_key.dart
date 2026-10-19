part of '../cipher_bird.dart';

/// A 32-byte symmetric key with the safe choices built in.
///
/// Encryption is the **key-committing** AEAD (a ciphertext can only ever open
/// under the one key that made it - no partitioning-oracle or "invisible
/// salamander" attacks). Passphrases are stretched with Argon2id at a
/// [SecurityProfile] cost. Sub-keys come from HKDF, so one key can safely serve
/// several purposes. The key lives in a [SecretBytes]; [destroy] wipes it.
///
/// ```dart
/// final key = SymmetricKey.generate();
/// final box = key.encryptText('meet at dawn');
/// final back = key.decryptText(box);
///
/// final salt = CipherBird.instance.easy.randomBytes(16);
/// final pk = SymmetricKey.fromPassphrase('correct horse battery staple', salt: salt);
/// ```
final class SymmetricKey {
  SymmetricKey._(this._lib, Uint8List key) : _secret = SecretBytes.take(key);

  /// A fresh random key.
  factory SymmetricKey.generate([CipherBird? lib]) {
    final l = _easyLib(lib);
    return SymmetricKey._(l, l.randomBytes(32));
  }

  /// Wrap existing 32-byte key material; copies the bytes.
  factory SymmetricKey.fromBytes(List<int> key, [CipherBird? lib]) {
    if (key.length != 32) {
      throw ArgumentError.value(key.length, 'key', 'a key is exactly 32 bytes');
    }
    return SymmetricKey._(_easyLib(lib), Uint8List.fromList(key));
  }

  /// From a hex string produced by [hex].
  factory SymmetricKey.fromHex(String hex, [CipherBird? lib]) =>
      SymmetricKey.fromBytes(fromHex(hex), lib);

  /// From a base64 string produced by [base64].
  factory SymmetricKey.fromBase64(String base64, [CipherBird? lib]) =>
      SymmetricKey.fromBytes(base64.base64Bytes, lib);

  /// Stretch a passphrase with Argon2id; [SymmetricKey.fromPassphraseBytes]
  /// is the byte form the caller can wipe afterwards.
  factory SymmetricKey.fromPassphrase(
    String passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
    int? ops,
    int? memoryBytes,
    CipherBird? lib,
  }) {
    final bytes = utf8.encode(passphrase);
    try {
      return SymmetricKey.fromPassphraseBytes(
        bytes,
        salt: salt,
        profile: profile,
        ops: ops,
        memoryBytes: memoryBytes,
        lib: lib,
      );
    } finally {
      bytes.wipe();
    }
  }

  /// Stretch a passphrase given as UTF-8 bytes with Argon2id. [salt] must be
  /// at least 16 random bytes stored next to the ciphertext (not secret);
  /// the same passphrase and salt always yield the same key. Cost comes from
  /// [profile] unless [ops] and [memoryBytes] override it. The caller keeps
  /// [passphrase] and should wipe it.
  factory SymmetricKey.fromPassphraseBytes(
    Uint8List passphrase, {
    required Uint8List salt,
    SecurityProfile profile = SecurityProfile.balanced,
    int? ops,
    int? memoryBytes,
    CipherBird? lib,
  }) {
    if (salt.length < 16) {
      throw ArgumentError.value(salt.length, 'salt', 'use at least 16 bytes');
    }
    final l = _easyLib(lib);
    final key = l.argon2idDeriveBytes(
      passphrase,
      salt,
      ops: ops ?? profile.argon2Ops,
      mem: memoryBytes ?? profile.argon2Memory,
    );
    return SymmetricKey._(l, key);
  }

  final CipherBird _lib;

  final SecretBytes _secret;

  Uint8List get _key => _secret.bytes;
}
