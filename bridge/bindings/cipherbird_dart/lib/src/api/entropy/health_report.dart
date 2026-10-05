part of '../../cryptolib.dart';

/// SP 800-90B style health assessment of a file's raw entropy.
///
/// Use it to sanity-check a candidate entropy source *before* trusting it - a
/// photo of a blank wall will score far worse than one of a lava lamp. Passing
/// these checks is necessary, not sufficient: they catch obviously-degenerate
/// sources, not subtle bias.
final class HealthReport {
  const HealthReport({
    required this.minEntropyPerByte,
    required this.longestRun,
    required this.maxWindowCount,
    required this.rctPassed,
    required this.aptPassed,
  });

  /// Most-Common-Value lower bound on min-entropy, in bits per byte (0..8).
  /// Higher is better; 8.0 is the theoretical maximum.
  final double minEntropyPerByte;

  /// Longest run of identical samples observed.
  final int longestRun;

  /// Largest count seen in the adaptive-proportion window.
  final int maxWindowCount;

  /// Repetition Count Test passed (SP 800-90B §4.4.1).
  final bool rctPassed;

  /// Adaptive Proportion Test passed (SP 800-90B §4.4.2).
  final bool aptPassed;

  /// Both statistical health tests passed. Still only a floor, not a warranty.
  bool get healthy => rctPassed && aptPassed;
}
