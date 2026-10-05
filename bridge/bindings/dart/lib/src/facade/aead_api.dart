part of '../../cryptolib_ffi.dart';

/// Authenticated symmetric encryption, incl. committing and streaming modes.
extension type AeadApi(CryptoLib _l) {
  /// Generate a 32-byte random symmetric key.
  Uint8List symKeygen() => _l.symKeygen();

  /// XChaCha20-Poly1305 encrypt.
  Uint8List xchacha20Encrypt(Uint8List plaintext, Uint8List key,
          [Uint8List? aad]) =>
      _l.xchacha20Encrypt(plaintext, key, aad);

  /// XChaCha20-Poly1305 decrypt.
  Uint8List xchacha20Decrypt(Uint8List ciphertext, Uint8List key,
          [Uint8List? aad]) =>
      _l.xchacha20Decrypt(ciphertext, key, aad);

  /// AES-256-GCM encrypt.
  Uint8List aes256gcmEncrypt(Uint8List plaintext, Uint8List key,
          [Uint8List? aad]) =>
      _l.aes256gcmEncrypt(plaintext, key, aad);

  /// AES-256-GCM decrypt.
  Uint8List aes256gcmDecrypt(Uint8List ciphertext, Uint8List key,
          [Uint8List? aad]) =>
      _l.aes256gcmDecrypt(ciphertext, key, aad);

  /// Check if AES-256-GCM is available on this CPU.
  bool aes256gcmAvailable() => _l.aes256gcmAvailable();

  /// Committing AEAD encrypt. Unlike a plain AEAD, the ciphertext binds the
  /// exact key, so it cannot be opened under a second key (no invisible
  /// salamander / partitioning-oracle attack). [key] is 32 bytes.
  Uint8List committingEncrypt(Uint8List plaintext, Uint8List key,
          [Uint8List? aad]) =>
      _l.committingEncrypt(plaintext, key, aad);

  /// Committing AEAD decrypt. Throws if the key/AAD don't match or the
  /// commitment check fails. [key] is 32 bytes.
  Uint8List committingDecrypt(Uint8List ciphertext, Uint8List key,
          [Uint8List? aad]) =>
      _l.committingDecrypt(ciphertext, key, aad);

  /// Streaming encrypt: encrypt chunks of data with ordering.
  /// Returns (header, encryptedChunks).
  (Uint8List header, List<Uint8List> chunks) streamEncrypt(
          Uint8List key, List<Uint8List> plaintextChunks) =>
      _l.streamEncrypt(key, plaintextChunks);

  /// Streaming decrypt: decrypt chunks of data.
  List<Uint8List> streamDecrypt(
          Uint8List key, Uint8List header, List<Uint8List> ciphertextChunks) =>
      _l.streamDecrypt(key, header, ciphertextChunks);
}
