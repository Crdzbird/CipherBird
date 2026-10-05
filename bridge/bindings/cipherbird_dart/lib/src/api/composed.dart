part of '../cipher_bird.dart';

/// Composed seal/open operations on CipherBird.
extension CipherBirdComposed on CipherBird {
  /// FEC-encode [data] under [scheme]. Apply before embedding when the carrier
  /// may be degraded in transit.
  Uint8List fecEncode(Uint8List data, FecScheme scheme) {
    final d = _toNative(data);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, int)
        >('cryptolib_fec_encode')(d, data.length, scheme.value),
      );
    } finally {
      if (d != nullptr) {
        calloc.free(d);
      }
    }
  }

  /// FEC-decode [data], recovering [originalLength] bytes. [scheme] and
  /// [originalLength] must match what [fecEncode] was given.
  Uint8List fecDecode(Uint8List data, FecScheme scheme, int originalLength) {
    final d = _toNative(data);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Int32, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, int, int)
        >('cryptolib_fec_decode')(d, data.length, scheme.value, originalLength),
      );
    } finally {
      if (d != nullptr) {
        calloc.free(d);
      }
    }
  }
}
