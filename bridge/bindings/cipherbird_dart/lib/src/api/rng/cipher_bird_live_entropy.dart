part of '../../cipher_bird.dart';

/// Live entropy sources on CipherBird.
extension CipherBirdLiveEntropy on CipherBird {
  /// A [LiveEntropy] source under a policy: chunks below [minBitsPerByte] of
  /// min-entropy are not credited, nor, with [requireRct], chunks that fail
  /// the repetition-count test; the generator seeds after [minCreditedBits].
  LiveEntropy liveEntropy({
    double minBitsPerByte = 1.0,
    bool requireRct = true,
    double minCreditedBits = 256.0,
  }) {
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
              Double,
              Int32,
              Double,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(double, int, double, Pointer<Pointer<Utf8>>)
          >('cryptolib_live_entropy_new')(
            minBitsPerByte,
            requireRct ? 1 : 0,
            minCreditedBits,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(msg);
      }
      return LiveEntropy._(this, h);
    } finally {
      calloc.free(errPtr);
    }
  }

  String _takeString(Pointer<Utf8> p) {
    if (p == nullptr) {
      return '';
    }
    final s = p.toDartString();
    _core.strFree(p);
    return s;
  }

  LiveFeedReport _liveFeedReport(CipherBirdLiveFeedReport r) {
    if (r.error != nullptr) {
      throw Exception(_takeString(r.error));
    }
    return LiveFeedReport(
      accepted: r.accepted == 1,
      creditedBits: r.creditedBits,
      creditedBitsTotal: r.creditedBitsTotal,
      ready: r.ready == 1,
      minEntropyPerByte: r.minEntropyPerByte,
      longestRun: r.longestRun,
      rctCutoff: r.rctCutoff,
      rctPassed: r.rctPassed == 1,
      aptPassed: r.aptPassed == 1,
      reason: _takeString(r.reason),
    );
  }

  LiveStatus _liveStatus(CipherBirdLiveStatus s) {
    if (s.error != nullptr) {
      throw Exception(_takeString(s.error));
    }
    return LiveStatus(
      chunksFed: s.chunksFed,
      chunksAccepted: s.chunksAccepted,
      chunksRejected: s.chunksRejected,
      bytesFed: s.bytesFed,
      reseeds: s.reseeds,
      creditedBitsTotal: s.creditedBitsTotal,
      creditedBitsSinceReseed: s.creditedBitsSinceReseed,
      minCreditedBits: s.minCreditedBits,
      ready: s.ready == 1,
      lastMinEntropyPerByte: s.lastMinEntropyPerByte,
      lastLongestRun: s.lastLongestRun,
      lastRctCutoff: s.lastRctCutoff,
      lastReason: _takeString(s.lastReason),
    );
  }
}
