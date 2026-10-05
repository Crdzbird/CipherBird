part of '../../cipher_bird.dart';

/// Incremental BLAKE3. The digest equals `blake3()` over the concatenation of
/// every [update]. Not thread-safe; call [close] when done.
final class Blake3Hasher {
  Blake3Hasher._(this._lib, this._h);
  final CipherBird _lib;
  Pointer<Void> _h;

  /// Feed bytes. Throws after [finalize].
  void update(Uint8List data) {
    final p = _lib._toNative(data);
    try {
      final ok = _lib._lib
          .lookupFunction<
            Int32 Function(Pointer<Void>, Pointer<Uint8>, Size),
            int Function(Pointer<Void>, Pointer<Uint8>, int)
          >('cryptolib_blake3_hasher_update')(_h, p, data.length);
      if (ok != 1) {
        throw Exception(
          'cipherbird: blake3 update failed (closed or finalized?)',
        );
      }
    } finally {
      if (p != nullptr) {
        calloc.free(p);
      }
    }
  }

  /// Produce the digest; [outLen] 0 means 32 bytes, larger uses extendable
  /// output. The hasher accepts no further updates afterwards.
  Uint8List finalize({int outLen = 0}) => _lib._checkBufResult(
    _lib._lib.lookupFunction<
      CipherBirdBufferResult Function(Pointer<Void>, Size),
      CipherBirdBufferResult Function(Pointer<Void>, int)
    >('cryptolib_blake3_hasher_finalize')(_h, outLen),
  );

  /// Release the native handle. Idempotent.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_blake3_hasher_free')(_h);
      _h = nullptr;
    }
  }
}
