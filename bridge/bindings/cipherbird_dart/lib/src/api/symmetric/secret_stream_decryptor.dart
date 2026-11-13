part of '../../cipher_bird.dart';

/// The reading end of a SecretStream: chunks pulled one at a time in the
/// order they were written. A chunk that was tampered with, reordered,
/// duplicated, taken from another stream or cut short is rejected and the
/// state stays where it was, so only the right next chunk is accepted.
///
/// A stream is complete only when a chunk comes back with
/// [SecretStreamChunk.isFinal]: if the input ends while [isFinished] is
/// still false, the stream was truncated and what was read so far is not
/// the whole message. [close] releases the native state and wipes its key;
/// a finalizer does it if the object is dropped without one.
final class SecretStreamDecryptor implements Finalizable {
  SecretStreamDecryptor._(this._lib, this._handle) {
    _lib._handleFinalizer(_free).attach(this, _handle, size: _stateBytes);
  }

  static const _free = 'cryptolib_stream_dec_free';
  static const _stateBytes = 64;

  final CipherBird _lib;

  Pointer<Void> _handle;

  bool _finished = false;

  /// Whether [close] ran.
  bool get isClosed => _handle == nullptr;

  /// Whether the final chunk was read; false at the end of the input means
  /// the stream was truncated.
  bool get isFinished => _finished;

  /// Authenticates and decrypts the next chunk. Throws
  /// [SecretStreamException] with [SecretStreamError.invalid] for a chunk
  /// that does not belong here, and after [close] or after the final chunk.
  SecretStreamChunk pull(Uint8List ciphertext) {
    _lib._streamUsable(_handle, _finished);
    final p = _lib._toNative(ciphertext);
    final tag = calloc<Uint8>();
    try {
      final plaintext = _lib._streamBuf(
        _lib._symmetric.streamDecPull(_handle, p, ciphertext.length, tag),
        SecretStreamError.invalid,
      );
      final read = SecretStreamTag.fromValue(tag.value);
      _finished = read == SecretStreamTag.finalChunk;
      return SecretStreamChunk(plaintext, read);
    } finally {
      calloc.free(tag);
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Releases the native state, wiping its key. Idempotent.
  void close() {
    if (_handle == nullptr) {
      return;
    }
    _lib._handleFinalizer(_free).detach(this);
    _lib._symmetric.streamDecFree(_handle);
    _handle = nullptr;
  }
}
