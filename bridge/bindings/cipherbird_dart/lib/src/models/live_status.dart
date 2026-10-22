part of '../cipher_bird.dart';

/// Where a [LiveEntropy] source stands.
final class LiveStatus {
  const LiveStatus({
    required this.chunksFed,
    required this.chunksAccepted,
    required this.chunksRejected,
    required this.bytesFed,
    required this.reseeds,
    required this.creditedBitsTotal,
    required this.creditedBitsSinceReseed,
    required this.minCreditedBits,
    required this.ready,
    required this.lastMinEntropyPerByte,
    required this.lastLongestRun,
    required this.lastRctCutoff,
    required this.lastReason,
  });

  final int chunksFed;
  final int chunksAccepted;
  final int chunksRejected;
  final int bytesFed;

  /// How many times the generator was seeded or reseeded.
  final int reseeds;

  final double creditedBitsTotal;
  final double creditedBitsSinceReseed;

  /// Credit needed for the first seed and for each reseed.
  final double minCreditedBits;

  /// [LiveEntropy.generate] would succeed now.
  final bool ready;

  final double lastMinEntropyPerByte;
  final int lastLongestRun;
  final int lastRctCutoff;

  /// Why the last chunk was not credited; empty when it was.
  final String lastReason;
}
