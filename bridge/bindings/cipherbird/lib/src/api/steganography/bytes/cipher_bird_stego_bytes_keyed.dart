part of '../../../cipher_bird.dart';

/// Keyed and encrypted steganography on bytes.
extension CipherBirdStegoBytesKeyed on CipherBird {
  /// [stegoEmbedKeyed] on bytes: placement permuted under [key].
  Uint8List stegoEmbedKeyedBytes(
    Uint8List cover,
    MediaFormat format,
    Uint8List payload,
    Uint8List key,
  ) => _withScratch((s) {
    final out = s.reserve(format.extension);
    stegoEmbedKeyed(s.put(format.extension, cover), payload, out, key);
    return s.take(out);
  });

  /// [stegoExtractKeyed] on bytes.
  Uint8List stegoExtractKeyedBytes(
    Uint8List stego,
    MediaFormat format,
    Uint8List key,
  ) => _withScratch(
    (s) => stegoExtractKeyed(s.put(format.extension, stego), key),
  );

  /// [stegoEmbedEncrypted] on bytes: sealed under [masterKey], then hidden.
  Uint8List stegoEmbedEncryptedBytes(
    Uint8List cover,
    MediaFormat format,
    Uint8List plaintext,
    Uint8List masterKey,
  ) => _withScratch((s) {
    final out = s.reserve(format.extension);
    stegoEmbedEncrypted(
      s.put(format.extension, cover),
      plaintext,
      out,
      masterKey,
    );
    return s.take(out);
  });

  /// [stegoExtractDecrypt] on bytes.
  Uint8List stegoExtractDecryptBytes(
    Uint8List stego,
    MediaFormat format,
    Uint8List masterKey,
  ) => _withScratch(
    (s) => stegoExtractDecrypt(s.put(format.extension, stego), masterKey),
  );
}
