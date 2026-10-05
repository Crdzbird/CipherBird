part of '../../cryptolib.dart';

/// Entropy-source quality assessment.
extension CryptoLibEntropyHealth on CryptoLib {
  /// Assess the entropy health of [path], reading at most [maxBytes].
  ///
  /// Run this before using a media file as a key source; a low
  /// [HealthReport.minEntropyPerByte] or a failed test means the file is a poor
  /// source regardless of how large it is.
  HealthReport assessFileHealth(String path, {int maxBytes = 1 << 20}) {
    final p = path.toNativeUtf8();
    try {
      final r = _lib
          .lookupFunction<
            CryptoHealthReport Function(Pointer<Utf8>, Size),
            CryptoHealthReport Function(Pointer<Utf8>, int)
          >('cryptolib_entropy_assess_file_health')(p, maxBytes);
      if (r.error != nullptr) {
        final msg = r.error.toDartString();
        _core.strFree(r.error);
        throw Exception(msg);
      }
      return HealthReport(
        minEntropyPerByte: r.minEntropyPerByte,
        longestRun: r.longestRun,
        maxWindowCount: r.maxWindowCount,
        rctPassed: r.rctPassed == 1,
        aptPassed: r.aptPassed == 1,
      );
    } finally {
      calloc.free(p);
    }
  }
}
