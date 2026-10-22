import 'package:cipherbird/cipherbird.dart';

/// What the live meter draws: the last chunks as bars, the credit earned
/// towards the next seed, and the counters.
final class LiveMeterState {
  const LiveMeterState({
    this.bars = const [],
    this.creditedBits = 0,
    this.creditedSinceReseed = 0,
    this.minCredit = 256,
    this.reseeds = 0,
    this.chunks = 0,
    this.rejected = 0,
    this.ready = false,
    this.lastReason = '',
    this.source = 'nothing yet',
  });

  static const int keep = 48;

  /// One bar per chunk: bits of min-entropy per byte, and whether credited.
  final List<(double, bool)> bars;
  final double creditedBits;
  final double creditedSinceReseed;
  final double minCredit;
  final int reseeds;
  final int chunks;
  final int rejected;
  final bool ready;
  final String lastReason;
  final String source;

  /// Progress towards the first seed, or towards the next reseed.
  double get progress {
    final toward = reseeds == 0 ? creditedBits : creditedSinceReseed;
    return minCredit <= 0 ? 1 : (toward / minCredit).clamp(0, 1).toDouble();
  }

  /// The state after one more chunk was fed.
  LiveMeterState after(LiveFeedReport r, String source, double minCredit) {
    final next = [...bars, (r.minEntropyPerByte, r.accepted)];
    return LiveMeterState(
      bars: next.length > keep ? next.sublist(next.length - keep) : next,
      creditedBits: r.creditedBitsTotal,
      creditedSinceReseed: creditedSinceReseed + r.creditedBits,
      minCredit: minCredit,
      reseeds: reseeds,
      chunks: chunks + 1,
      rejected: rejected + (r.accepted ? 0 : 1),
      ready: r.ready,
      lastReason: r.reason,
      source: source,
    );
  }

  /// The state after the generator seeded or reseeded.
  LiveMeterState seeded(int reseeds) => LiveMeterState(
    bars: bars,
    creditedBits: creditedBits,
    creditedSinceReseed: reseeds == this.reseeds ? creditedSinceReseed : 0,
    minCredit: minCredit,
    reseeds: reseeds,
    chunks: chunks,
    rejected: rejected,
    ready: true,
    lastReason: lastReason,
    source: source,
  );
}
