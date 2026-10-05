part of '../../cryptolib.dart';

/// HMAC-DRBG (NIST SP 800-90A) accumulator.
///
/// Deterministic given the same `(entropy, nonce, personalization)` seed, so it
/// reproduces a stream exactly - useful for test vectors and reproducible
/// derivations. Call [close] when done; the handle holds native memory.
final class Drbg {
  Drbg._(this._lib, this._h);

  final CryptoLib _lib;
  Pointer<Void> _h;

  /// Generate [numBytes] (<= 65536) pseudo-random bytes, optionally mixing in
  /// [additional] input for this call only.
  Uint8List generate(int numBytes, [Uint8List? additional]) {
    final add = _toNativeOrNull(additional);
    try {
      return _lib._checkBufResult(
        _lib._lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(Pointer<Void>, int, Pointer<Uint8>, int)
        >('cryptolib_drbg_generate')(
          _h,
          numBytes,
          add,
          additional?.length ?? 0,
        ),
      );
    } finally {
      if (add != nullptr) {
        calloc.free(add);
      }
    }
  }

  /// Reseed with fresh [entropy] plus optional [additional] input.
  void reseed(Uint8List entropy, [Uint8List? additional]) {
    final e = _lib._toNative(entropy);
    final add = _toNativeOrNull(additional);
    try {
      _lib._checkResult(
        _lib._lib.lookupFunction<
          CryptoResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_drbg_reseed')(
          _h,
          e,
          entropy.length,
          add,
          additional?.length ?? 0,
        ),
      );
    } finally {
      if (e != nullptr) {
        calloc.free(e);
      }
      if (add != nullptr) {
        calloc.free(add);
      }
    }
  }

  /// Release the native handle. Idempotent; safe to call more than once.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >(
        'cryptolib_drbg_free',
      )(_h);
      _h = nullptr;
    }
  }

  Pointer<Uint8> _toNativeOrNull(Uint8List? b) =>
      (b == null || b.isEmpty) ? nullptr : _lib._toNative(b);
}
