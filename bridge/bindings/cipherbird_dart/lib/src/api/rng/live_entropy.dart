part of '../../cipher_bird.dart';

/// A continuous entropy source fed by a live stream.
///
/// Feed camera frames, audio buffers or any bytes as they arrive with
/// [feed]; every chunk is assessed under the policy and credited only when
/// it passes, with the reason given when it does not. [generate] draws from
/// an HMAC-DRBG seeded once [LiveStatus.minCreditedBits] have been earned
/// and reseeded as more credit arrives; it throws until then. Not safe to
/// use from two isolates at once. Call [close] when done.
final class LiveEntropy {
  LiveEntropy._(this._lib, this._h);

  final CipherBird _lib;
  Pointer<Void> _h;

  /// Assess, mix and (when the policy allows) credit one chunk from logical
  /// source [sourceId]; chunks under 1024 bytes are mixed but never credited.
  LiveFeedReport feed(Uint8List chunk, {int sourceId = 0}) {
    final d = _lib._toNative(chunk);
    try {
      final r = _lib._lib
          .lookupFunction<
            CipherBirdLiveFeedReport Function(
              Pointer<Void>,
              Pointer<Uint8>,
              Size,
              Uint8,
            ),
            CipherBirdLiveFeedReport Function(
              Pointer<Void>,
              Pointer<Uint8>,
              int,
              int,
            )
          >('cryptolib_live_entropy_feed')(_h, d, chunk.length, sourceId);
      return _lib._liveFeedReport(r);
    } finally {
      if (d != nullptr) {
        calloc.free(d);
      }
    }
  }

  /// Draw [numBytes] (at most 65536). Throws until the first seed is earned.
  Uint8List generate(int numBytes) => _lib._checkBufResult(
    _lib._lib.lookupFunction<
      CipherBirdBufferResult Function(Pointer<Void>, Size),
      CipherBirdBufferResult Function(Pointer<Void>, int)
    >('cryptolib_live_entropy_generate')(_h, numBytes),
  );

  /// Counters, credit and the last verdict.
  LiveStatus status() => _lib._liveStatus(
    _lib._lib.lookupFunction<
      CipherBirdLiveStatus Function(Pointer<Void>),
      CipherBirdLiveStatus Function(Pointer<Void>)
    >('cryptolib_live_entropy_status')(_h),
  );

  /// Release the native handle. Idempotent.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_live_entropy_free')(_h);
      _h = nullptr;
    }
  }
}
