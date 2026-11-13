part of '../../cipher_bird.dart';

/// The writing end of a SecretStream (libsodium
/// `crypto_secretstream_xchacha20poly1305`): chunks pushed one at a time,
/// each authenticated together with its position in the stream, so a reader
/// detects a tampered, reordered, duplicated, dropped or missing chunk.
///
/// Store or send [header] first, then every chunk [push] returns, in order.
/// End with [finish], whose final tag is what tells a reader the stream was
/// not cut short. A chunk is 17 bytes longer than its plaintext; chunk
/// boundaries are not hidden, so write the chunk length with each one.
/// [close] releases the native state and wipes its key; a finalizer does it
/// if the object is dropped without one.
final class SecretStreamEncryptor implements Finalizable {
  SecretStreamEncryptor._(this._lib, this._handle, this.header) {
    _lib._handleFinalizer(_free).attach(this, _handle, size: _stateBytes);
  }

  static const _free = 'cryptolib_stream_enc_free';
  static const _stateBytes = 128;

  final CipherBird _lib;

  Pointer<Void> _handle;

  bool _finished = false;

  /// The 24-byte header the reader needs before the first chunk. Not secret.
  final Uint8List header;

  /// Whether [close] ran.
  bool get isClosed => _handle == nullptr;

  /// Whether the final chunk was written.
  bool get isFinished => _finished;

  /// Encrypts one [chunk] and returns it with its 17-byte overhead. Throws
  /// [SecretStreamException] after [close] or after the final chunk.
  Uint8List push(
    Uint8List chunk, {
    SecretStreamTag tag = SecretStreamTag.message,
  }) {
    _lib._streamUsable(_handle, _finished);
    final p = _lib._toNative(chunk);
    try {
      final out = _lib._streamBuf(
        _lib._symmetric.streamEncPush(_handle, p, chunk.length, tag.value),
        SecretStreamError.internal,
      );
      _finished = tag == SecretStreamTag.finalChunk;
      return out;
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Writes the final chunk, empty unless [lastChunk] is given. Nothing can
  /// be pushed after it.
  Uint8List finish([Uint8List? lastChunk]) =>
      push(lastChunk ?? Uint8List(0), tag: SecretStreamTag.finalChunk);

  /// Releases the native state, wiping its key. Idempotent.
  void close() {
    if (_handle == nullptr) {
      return;
    }
    _lib._handleFinalizer(_free).detach(this);
    _lib._symmetric.streamEncFree(_handle);
    _handle = nullptr;
  }
}
