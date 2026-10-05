part of '../cipher_bird.dart';

/// PostQuantum operations.
extension CipherBirdPostQuantum on CipherBird {
  KeyPairResult mlKemKeygen(MlKemLevel level) => _extractKeyPair(
    _lib.lookupFunction<
      CryptoKeyPair Function(Int32),
      CryptoKeyPair Function(int)
    >('cryptolib_ml_kem_keygen')(level.value),
  );

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) mlKemEncapsulate(
    Uint8List publicKey,
    MlKemLevel level,
  ) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib
          .lookupFunction<
            CryptoKemEncapsResult Function(
              Pointer<Uint8>,
              Size,
              Int32,
              Pointer<Pointer<Utf8>>,
            ),
            CryptoKemEncapsResult Function(
              Pointer<Uint8>,
              int,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >(
            'cryptolib_ml_kem_encapsulate',
          )(pp, publicKey.length, level.value, errPtr);
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

  Uint8List mlKemDecapsulate(
    Uint8List ciphertext,
    Uint8List secretKey,
    MlKemLevel level,
  ) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Int32,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_ml_kem_decapsulate')(
          cp,
          ciphertext.length,
          sp,
          secretKey.length,
          level.value,
        ),
      );
    } finally {
      if (cp != nullptr) calloc.free(cp);
      if (sp != nullptr) calloc.free(sp);
    }
  }

  KeyPairResult hybridKemKeygen() => _extractKeyPair(
    _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
      'cryptolib_hybrid_kem_keygen',
    )(),
  );
}
