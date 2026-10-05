part of '../../../cipher_bird.dart';

extension CipherBirdOprfBlindWithScalar on CipherBird {
  /// Deterministic blind with a caller-supplied scalar (test vectors).
  OprfBlindResult oprfBlindWithScalar(Uint8List input, Uint8List blind) {
    final p = _toNative(input), b = _toNative(blind);
    try {
      final c = _lib
          .lookupFunction<
            CipherBirdOprfBlind Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            CipherBirdOprfBlind Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >(
            'cryptolib_oprf_blind_with_scalar',
          )(p, input.length, b, blind.length);
      return _oprfBlindOut(c);
    } finally {
      if (p != nullptr) calloc.free(p);
      if (b != nullptr) calloc.free(b);
    }
  }
}
