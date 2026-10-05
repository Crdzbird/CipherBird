part of '../../cipher_bird.dart';

/// PostQuantum operations.
extension CipherBirdSntrupX25519 on CipherBird {
  Uint8List sntrupX25519Decapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_sntrup_x25519_decapsulate')(
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

  KeyPairResult sntrupX25519Keygen() => _extractKeyPair(
    _lib.lookupFunction<
      CipherBirdKeyPair Function(),
      CipherBirdKeyPair Function()
    >(
      'cryptolib_sntrup_x25519_keygen',
    )(),
  );

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) sntrupX25519Encapsulate(Uint8List publicKey) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib
          .lookupFunction<
            CipherBirdKemEncapsResult Function(
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            CipherBirdKemEncapsResult Function(
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >(
            'cryptolib_sntrup_x25519_encapsulate',
          )(pp, publicKey.length, errPtr);
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
}
