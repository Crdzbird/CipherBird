part of '../../cipher_bird.dart';

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
/// final salt = CipherBird.instance.easy.randomBytes(16);
/// final pk = SymmetricKey.fromPassphrase('correct horse battery staple', salt: salt);
/// ```
extension SymmetricKeyEncryption on SymmetricKey {
  /// Encrypt with the key-committing AEAD. [aad] is authenticated but not
  /// encrypted (a header, an id - anything that must match on decrypt).
  Uint8List encrypt(List<int> plaintext, {List<int>? aad}) =>
      _lib.committingEncrypt(plaintext.u8, _key, aad?.u8);

  /// Decrypt. Throws if the key, the data or [aad] do not match.
  Uint8List decrypt(List<int> ciphertext, {List<int>? aad}) =>
      _lib.committingDecrypt(ciphertext.u8, _key, aad?.u8);

  /// Encrypt a string; returns base64 you can store or send as text.
  String encryptText(String plaintext, {String? aad}) =>
      encrypt(plaintext.bytes, aad: aad?.bytes).base64;

  /// Decrypt a string made by [encryptText].
  String decryptText(String ciphertextBase64, {String? aad}) =>
      decrypt(ciphertextBase64.base64Bytes, aad: aad?.bytes).text;

  /// Use this key as a [CipherBirdRecipe] key source: `lib.recipe().withKeySource(key.asKeySource)`.
  KeySource get asKeySource => RawKeySource(_key);

  /// Zero the key bytes. The object is unusable afterwards.
  void destroy() => _key.wipe();
}
