part of '../../../cipher_bird.dart';

extension CipherBirdOprfEvaluate on CipherBird {
  /// Server one-shot: compute the PRF output directly from the key + input.
  Uint8List oprfEvaluate(Uint8List secretKey, Uint8List input) {
    final s = _toNative(secretKey), p = _toNative(input);
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
        >('cryptolib_oprf_evaluate')(s, secretKey.length, p, input.length),
      );
    } finally {
      if (s != nullptr) calloc.free(s);
      if (p != nullptr) calloc.free(p);
    }
  }
}
