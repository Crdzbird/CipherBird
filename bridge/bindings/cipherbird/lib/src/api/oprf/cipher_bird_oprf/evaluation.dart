part of '../../../cipher_bird.dart';

/// OPRF (RFC 9497) methods on CipherBird.
extension CipherBirdOprfEvaluation on CipherBird {
  /// Server: evaluate a blinded element under the secret key.
  Uint8List oprfBlindEvaluate(Uint8List secretKey, Uint8List blindedElement) {
    final s = _toNative(secretKey), b = _toNative(blindedElement);
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
        >('cryptolib_oprf_blind_evaluate')(
          s,
          secretKey.length,
          b,
          blindedElement.length,
        ),
      );
    } finally {
      if (s != nullptr) calloc.free(s);
      if (b != nullptr) calloc.free(b);
    }
  }

  /// Client: unblind the evaluated element -> 64-byte PRF output.
  Uint8List oprfFinalize(
    Uint8List input,
    Uint8List blind,
    Uint8List evaluatedElement,
  ) {
    final p = _toNative(input),
        b = _toNative(blind),
        e = _toNative(evaluatedElement);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
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
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_oprf_finalize')(
          p,
          input.length,
          b,
          blind.length,
          e,
          evaluatedElement.length,
        ),
      );
    } finally {
      if (p != nullptr) calloc.free(p);
      if (b != nullptr) calloc.free(b);
      if (e != nullptr) {
        calloc.free(e);
      }
    }
  }
}
