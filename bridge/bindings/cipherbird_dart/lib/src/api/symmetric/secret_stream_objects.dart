part of '../../cipher_bird.dart';

/// Incremental SecretStream: an encryptor and a decryptor that take one
/// chunk at a time, so a recording of any size passes through in constant
/// memory. [CipherBirdSecretStream.streamEncrypt] is the same stream with
/// every chunk in one list.
extension CipherBirdSecretStreamObjects on CipherBird {
  /// Bytes of a SecretStream key.
  static const int keyBytes = 32;

  /// Bytes of the header an encryptor emits and a decryptor needs.
  static const int headerBytes = 24;

  /// Bytes a chunk grows by when encrypted.
  static const int chunkOverhead = 17;

  /// A new stream under a 32-byte [key]. The native copy of the key is wiped
  /// as soon as the stream state is derived from it.
  SecretStreamEncryptor secretStreamEncryptor(Uint8List key) {
    _streamLength(key, keyBytes, 'the key must be 32 bytes');
    final pk = _toNative(key);
    try {
      final handle = _symmetric.streamEncCreate(pk);
      if (handle == nullptr) {
        throw const SecretStreamException(SecretStreamError.internal);
      }
      try {
        final header = _streamBuf(
          _symmetric.streamEncHeader(handle),
          SecretStreamError.internal,
        );
        return SecretStreamEncryptor._(this, handle, header);
      } on SecretStreamException {
        _symmetric.streamEncFree(handle);
        rethrow;
      }
    } finally {
      calloc.free(pk);
    }
  }

  /// A reader for the stream that began with [header], under the same
  /// 32-byte [key].
  SecretStreamDecryptor secretStreamDecryptor(Uint8List key, Uint8List header) {
    _streamLength(key, keyBytes, 'the key must be 32 bytes');
    _streamLength(header, headerBytes, 'the header must be 24 bytes');
    final pk = _toNative(key);
    final ph = _toNative(header);
    try {
      final handle = _symmetric.streamDecCreate(pk, ph);
      if (handle == nullptr) {
        throw const SecretStreamException(SecretStreamError.internal);
      }
      return SecretStreamDecryptor._(this, handle);
    } finally {
      calloc.free(pk);
      calloc.free(ph);
    }
  }
}
