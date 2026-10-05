part of '../../cipher_bird.dart';

/// Composed seal/open operations on CipherBird.
extension CipherBirdComposedImageFactorSeal on CipherBird {
  /// Seal [plaintext] behind two factors: the OPRF secret [oprfSecretSeed]
  /// (something you know) and the exact [referenceImagePath] (something you
  /// have). The ciphertext is hidden in [coverPath] -> [outputPath].
  ///
  /// Both factors are required to open; neither alone reveals anything.
  void imageFactorSeal({
    required Uint8List oprfSecretSeed,
    required String referenceImagePath,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
  }) {
    final seed = _toNative(oprfSecretSeed);
    final ref = referenceImagePath.toNativeUtf8();
    final pt = _toNative(plaintext);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final cv = coverPath.toNativeUtf8();
    final out = outputPath.toNativeUtf8();
    try {
      _checkResult(
        _lib.lookupFunction<
          CryptoResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Utf8>,
          ),
          CryptoResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Utf8>,
          )
        >('cryptolib_image_factor_seal')(
          seed,
          oprfSecretSeed.length,
          ref,
          pt,
          plaintext.length,
          a,
          aad?.length ?? 0,
          cv,
          out,
        ),
      );
    } finally {
      if (seed != nullptr) {
        calloc.free(seed);
      }
      calloc.free(ref);
      if (pt != nullptr) {
        calloc.free(pt);
      }
      if (a != nullptr) {
        calloc.free(a);
      }
      calloc.free(cv);
      calloc.free(out);
    }
  }
}
