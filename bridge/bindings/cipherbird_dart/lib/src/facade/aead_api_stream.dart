part of '../cipher_bird.dart';

/// The incremental SecretStream on `lib.aead`.
extension AeadApiStream on AeadApi {
  /// A new stream under a 32-byte [key]; push chunks one at a time.
  SecretStreamEncryptor streamEncryptor(Uint8List key) =>
      _l.secretStreamEncryptor(key);

  /// A reader for the stream that began with [header].
  SecretStreamDecryptor streamDecryptor(Uint8List key, Uint8List header) =>
      _l.secretStreamDecryptor(key, header);
}
