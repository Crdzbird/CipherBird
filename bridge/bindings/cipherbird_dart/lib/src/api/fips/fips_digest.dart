part of '../../cipher_bird.dart';

/// FIPS profile digests on CipherBird (OpenSSL FIPS Provider, fips=yes).
extension CipherBirdFipsDigest on CipherBird {
  /// Digest [data] with [hash].
  Uint8List fipsDigest(FipsHash hash, Uint8List data) {
    final dataPtr = _toNative(data);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Int32, Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(int, Pointer<Uint8>, int)
        >('cryptolib_fips_digest')(hash.value, dataPtr, data.length),
      );
    } finally {
      if (dataPtr != nullptr) calloc.free(dataPtr);
    }
  }

  /// HMAC of [data] under [key] (at least 14 bytes).
  Uint8List fipsHmac(FipsHash hash, Uint8List key, Uint8List data) {
    final keyPtr = _toNative(key);
    final dataPtr = _toNative(data);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Int32,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_fips_hmac')(
          hash.value,
          keyPtr,
          key.length,
          dataPtr,
          data.length,
        ),
      );
    } finally {
      if (keyPtr != nullptr) calloc.free(keyPtr);
      if (dataPtr != nullptr) calloc.free(dataPtr);
    }
  }
}
