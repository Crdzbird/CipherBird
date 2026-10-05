part of '../../cryptolib.dart';

/// Composed seal/open operations on CryptoLib.
extension CryptoLibComposedImageFactorOpen on CryptoLib {
  /// Recover an [imageFactorSeal]ed message. Needs the same secret seed, the
  /// same reference image, and the same [aad].
  Uint8List imageFactorOpen({
    required Uint8List oprfSecretSeed,
    required String referenceImagePath,
    required String stegoPath,
    Uint8List? aad,
  }) {
    final seed = _toNative(oprfSecretSeed);
    final ref = referenceImagePath.toNativeUtf8();
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final sp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
          )
        >('cryptolib_image_factor_open')(
          seed,
          oprfSecretSeed.length,
          ref,
          a,
          aad?.length ?? 0,
          sp,
        ),
      );
    } finally {
      if (seed != nullptr) {
        calloc.free(seed);
      }
      calloc.free(ref);
      if (a != nullptr) {
        calloc.free(a);
      }
      calloc.free(sp);
    }
  }
}
