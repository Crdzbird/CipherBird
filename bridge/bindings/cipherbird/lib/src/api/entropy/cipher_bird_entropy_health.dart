part of '../../cipher_bird.dart';

/// Entropy-source quality assessment.
extension CipherBirdEntropyHealth on CipherBird {
  /// Assess the entropy health of [path], reading at most [maxBytes], with
  /// the local tests calibrated against [floorBitsPerByte].
  ///
  /// Run this before using a media file as a key source; a low
  /// [HealthReport.minEntropyPerByte] or a failed test means the file is a poor
  /// source regardless of how large it is. [HealthReport.summary] explains the
  /// verdict. Against an engine that predates the calibrated report the
  /// older figures are returned and the cutoffs read 0.
  HealthReport assessFileHealth(
    String path, {
    int maxBytes = 1 << 20,
    double floorBitsPerByte = 1.0,
  }) {
    final p = path.toNativeUtf8();
    try {
      return _healthV2(p, maxBytes, floorBitsPerByte) ?? _healthV1(p, maxBytes);
    } finally {
      calloc.free(p);
    }
  }

  HealthReport? _healthV2(Pointer<Utf8> p, int maxBytes, double floor) {
    final CipherBirdHealthReport2 Function(Pointer<Utf8>, int, double) fn;
    try {
      fn = _lib
          .lookupFunction<
            CipherBirdHealthReport2 Function(Pointer<Utf8>, Size, Double),
            CipherBirdHealthReport2 Function(Pointer<Utf8>, int, double)
          >('cryptolib_entropy_assess_file_health_v2');
    } catch (e) {
      if (e is! ArgumentError) {
        rethrow;
      }
      return null;
    }
    final r = fn(p, maxBytes, floor);
    if (r.error != nullptr) {
      final msg = r.error.toDartString();
      _core.strFree(r.error);
      throw Exception(msg);
    }
    final summary = r.summary == nullptr ? '' : r.summary.toDartString();
    if (r.summary != nullptr) {
      _core.strFree(r.summary);
    }
    return HealthReport(
      minEntropyPerByte: r.minEntropyPerByte,
      mcvBitsPerByte: r.mcvBitsPerByte,
      markovBitsPerByte: r.markovBitsPerByte,
      floorBitsPerByte: r.floorBitsPerByte,
      sampleBytes: r.sampleBytes,
      longestRun: r.longestRun,
      rctCutoff: r.rctCutoff,
      maxWindowCount: r.maxWindowCount,
      aptCutoff: r.aptCutoff,
      aptWindow: r.aptWindow,
      rctPassed: r.rctPassed == 1,
      aptPassed: r.aptPassed == 1,
      summary: summary,
    );
  }

  HealthReport _healthV1(Pointer<Utf8> p, int maxBytes) {
    final r = _lib
        .lookupFunction<
          CipherBirdHealthReport Function(Pointer<Utf8>, Size),
          CipherBirdHealthReport Function(Pointer<Utf8>, int)
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
  }
}
