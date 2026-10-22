part of '../../cipher_bird.dart';

/// Media entropy harvest with an explicit source policy on CipherBird.
extension CipherBirdEntropyPolicy on CipherBird {
  /// Harvests [path] like [entropyFromFile] (or
  /// [entropyFromFileDeterministic] when [deterministic]) under a policy:
  /// the file is refused below [minBitsPerByte] of SP 800-90B min-entropy
  /// (the plain harvests use 1.0; 0 accepts any file) and, with
  /// [requireRct], when it fails the repetition-count test. The
  /// adaptive-proportion test is reported, never required.
  Pointer<Void> entropyFromFileWithPolicy(
    String path, {
    bool deterministic = false,
    double minBitsPerByte = 1.0,
    bool requireRct = true,
  }) {
    final cp = path.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
              Pointer<Utf8>,
              Int32,
              Double,
              Int32,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
              Pointer<Utf8>,
              int,
              double,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_entropy_from_file_with_policy')(
            cp,
            deterministic ? 1 : 0,
            minBitsPerByte,
            requireRct ? 1 : 0,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      calloc.free(cp);
      calloc.free(errPtr);
    }
  }
}
