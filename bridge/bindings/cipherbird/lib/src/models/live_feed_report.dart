part of '../cipher_bird.dart';

/// What one [LiveEntropy.feed] did with a chunk.
final class LiveFeedReport {
  const LiveFeedReport({
    required this.accepted,
    required this.creditedBits,
    required this.creditedBitsTotal,
    required this.ready,
    required this.minEntropyPerByte,
    required this.longestRun,
    required this.rctCutoff,
    required this.rctPassed,
    required this.aptPassed,
    required this.reason,
  });

  /// The chunk passed the policy and was credited.
  final bool accepted;

  /// Bits of min-entropy this chunk was credited with.
  final double creditedBits;

  /// Credited bits since the source was created.
  final double creditedBitsTotal;

  /// [LiveEntropy.generate] would succeed now.
  final bool ready;

  /// This chunk's min-entropy estimate, bits per byte.
  final double minEntropyPerByte;

  /// Longest run of one byte, including the run carried from the previous chunk.
  final int longestRun;

  /// A run this long fails the repetition-count test.
  final int rctCutoff;

  /// Repetition-count test verdict for this chunk.
  final bool rctPassed;

  /// Adaptive-proportion test verdict for this chunk (informational).
  final bool aptPassed;

  /// Why the chunk was not credited; empty when it was.
  final String reason;
}
