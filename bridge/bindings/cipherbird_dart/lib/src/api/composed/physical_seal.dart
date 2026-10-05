part of '../../cipher_bird.dart';

/// Composed seal/open operations on CipherBird.
extension CipherBirdComposedPhysicalSeal on CipherBird {
  /// Seal [plaintext] under a key derived from [keyMediaPath], hiding the
  /// result inside [coverPath] and writing it to [outputPath].
  ///
  /// Opening needs BOTH files: the key media (which never leaves your hands)
  /// and the carrier. The key file is conditioned deterministically, so the
  /// same file always yields the same key and nothing needs to be stored.
  void physicalSeal({
    required String keyMediaPath,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
  }) {
    final km = keyMediaPath.toNativeUtf8();
    final pt = _toNative(plaintext);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final cv = coverPath.toNativeUtf8();
    final out = outputPath.toNativeUtf8();
    try {
      _checkResult(
        _lib.lookupFunction<
          CipherBirdResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Utf8>,
          ),
          CipherBirdResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Utf8>,
          )
        >('cryptolib_physical_seal')(
          km,
          pt,
          plaintext.length,
          a,
          aad?.length ?? 0,
          cv,
          out,
        ),
      );
    } finally {
      calloc.free(km);
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
