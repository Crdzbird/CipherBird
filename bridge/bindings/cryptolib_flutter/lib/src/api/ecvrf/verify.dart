part of '../../cryptolib.dart';

/// ECVRF (RFC 9381) methods on CryptoLib.
extension CryptoLibEcvrfVerify on CryptoLib {
  /// Verify: returns the 64-byte beta on success; throws if the proof is invalid.
  Uint8List ecvrfVerify(Uint8List publicKey, Uint8List alpha, Uint8List proof) {
    final pk = _toNative(publicKey),
        pa = _toNative(alpha),
        pi = _toNative(proof);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_ecvrf_verify')(
          pk,
          publicKey.length,
          pa,
          alpha.length,
          pi,
          proof.length,
        ),
      );
    } finally {
      if (pk != nullptr) {
        calloc.free(pk);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
      if (pi != nullptr) {
        calloc.free(pi);
      }
    }
  }
}
