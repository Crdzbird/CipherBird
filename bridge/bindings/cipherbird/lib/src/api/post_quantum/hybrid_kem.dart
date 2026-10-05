part of '../../cryptolib.dart';

/// PostQuantum operations.
extension CryptoLibHybridKem on CryptoLib {
  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) hybridKemEncapsulate(Uint8List publicKey) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib
          .lookupFunction<
            CryptoKemEncapsResult Function(
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            CryptoKemEncapsResult Function(
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_hybrid_kem_encapsulate')(pp, publicKey.length, errPtr);
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      return (_copyBuf(r.ciphertext), _copyBuf(r.sharedSecret));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(errPtr);
    }
  }

  Uint8List hybridKemDecapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_hybrid_kem_decapsulate')(
          cp,
          ciphertext.length,
          sp,
          secretKey.length,
        ),
      );
    } finally {
      if (cp != nullptr) calloc.free(cp);
      if (sp != nullptr) calloc.free(sp);
    }
  }
}
