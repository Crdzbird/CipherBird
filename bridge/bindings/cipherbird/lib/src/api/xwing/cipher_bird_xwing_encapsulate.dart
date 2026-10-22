part of '../../cipher_bird.dart';

/// X-Wing encapsulation on CipherBird.
extension CipherBirdXWingEncapsulate on CipherBird {
  /// Returns (ciphertext 1120 bytes, sharedSecret 32 bytes).
  (Uint8List, Uint8List) xwingEncapsulate(Uint8List publicKey) {
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
          >('cryptolib_xwing_encapsulate')(pp, publicKey.length, errPtr);
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
