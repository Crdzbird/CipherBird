part of '../../../cryptolib.dart';

/// OPRF (RFC 9497) methods on CryptoLib.
extension CryptoLibOprfEvaluation on CryptoLib {
  /// Server: evaluate a blinded element under the secret key.
  Uint8List oprfBlindEvaluate(Uint8List secretKey, Uint8List blindedElement) {
    final s = _toNative(secretKey), b = _toNative(blindedElement);
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

  /// Server one-shot: compute the PRF output directly from the key + input.
  Uint8List oprfEvaluate(Uint8List secretKey, Uint8List input) {
    final s = _toNative(secretKey), p = _toNative(input);
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
        >('cryptolib_oprf_evaluate')(s, secretKey.length, p, input.length),
      );
    } finally {
      if (s != nullptr) calloc.free(s);
      if (p != nullptr) calloc.free(p);
    }
  }
}
