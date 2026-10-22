part of '../../cipher_bird.dart';

/// FIPS profile key derivation on CipherBird.
extension CipherBirdFipsKdf on CipherBird {
  /// HKDF extract-and-expand (SP 800-56C r2).
  Uint8List fipsHkdf(
    FipsHash hash,
    Uint8List ikm,
    int outLen, {
    Uint8List? salt,
    Uint8List? info,
  }) {
    final ikmPtr = _toNative(ikm);
    final saltPtr = salt == null ? nullptr : _toNative(salt);
    final infoPtr = info == null ? nullptr : _toNative(info);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Int32,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Size,
          ),
          CipherBirdBufferResult Function(
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_fips_hkdf')(
          hash.value,
          ikmPtr,
          ikm.length,
          saltPtr,
          salt?.length ?? 0,
          infoPtr,
          info?.length ?? 0,
          outLen,
        ),
      );
    } finally {
      if (ikmPtr != nullptr) calloc.free(ikmPtr);
      if (saltPtr != nullptr) calloc.free(saltPtr);
      if (infoPtr != nullptr) calloc.free(infoPtr);
    }
  }
}
