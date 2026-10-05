part of '../cryptolib.dart';

/// A 32-byte symmetric key with the safe choices built in.
///
/// Encryption is the **key-committing** AEAD (a ciphertext can only ever open
/// under the one key that made it - no partitioning-oracle or "invisible
/// salamander" attacks). Passphrases are stretched with Argon2id at a
/// [SecurityProfile] cost. Sub-keys come from HKDF, so one key can safely serve
/// several purposes.
///
/// ```dart
/// final key = SymmetricKey.generate();
/// final box = key.encryptText('meet at dawn');
/// final back = key.decryptText(box);
///
/// final salt = CryptoLib.instance.easy.randomBytes(16);
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
      throw ArgumentError.value(
        key.length,
        'key',
        'a SymmetricKey is exactly 32 bytes',
      );
    }
    return SymmetricKey._(_easyLib(lib), Uint8List.fromList(key));
  }

  /// From a hex string produced by [hex].
  factory SymmetricKey.fromHex(String hex, [CryptoLib? lib]) =>
      SymmetricKey.fromBytes(fromHex(hex), lib);

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
      throw ArgumentError.value(
        salt.length,
        'salt',
        'use at least 16 random bytes',
      );
    }
    final l = _easyLib(lib);
    return SymmetricKey._(
      l,
      l.argon2idDerive(
        passphrase,
        salt,
        ops: ops ?? profile.argon2Ops,
        mem: memoryBytes ?? profile.argon2Memory,
      ),
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

  /// An independent sub-key for [purpose] (HKDF). Same key + same purpose ->
  /// same sub-key; different purposes never collide. Use it to give each
  /// feature of your app its own key from one root.
  SymmetricKey derive(String purpose) =>
      SymmetricKey._(_lib, _lib.hkdfDerive(_key, info: purpose.bytes));
}
