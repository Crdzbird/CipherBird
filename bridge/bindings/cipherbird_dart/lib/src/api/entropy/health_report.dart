part of '../../cipher_bird.dart';

/// SP 800-90B style health assessment of a file's raw entropy, with every
/// number behind the verdict.
///
/// Use it to sanity-check a candidate entropy source *before* trusting it - a
/// photo of a blank wall will score far worse than one of a lava lamp. Passing
/// these checks is necessary, not sufficient: they catch obviously-degenerate
/// sources, not subtle bias. The two local tests are calibrated against
/// [floorBitsPerByte], the min-entropy the caller claims, so [rctCutoff] is
/// 1 + ceil(30 / floor) and a run that long fails the repetition-count test.
final class HealthReport {
  const HealthReport({
    required this.minEntropyPerByte,
    required this.longestRun,
    required this.maxWindowCount,
    required this.rctPassed,
    required this.aptPassed,
    this.mcvBitsPerByte = 0,
    this.markovBitsPerByte = 0,
    this.floorBitsPerByte = 1,
    this.sampleBytes = 0,
    this.rctCutoff = 0,
    this.aptCutoff = 0,
    this.aptWindow = 512,
    this.summary = '',
  });

  /// Lower bound on min-entropy, in bits per byte (0..8): the smaller of the
  /// Most-Common-Value and the Markov estimates. 8.0 is the maximum.
  final double minEntropyPerByte;

  /// Most-Common-Value estimate (SP 800-90B 6.3.1), bits per byte.
  final double mcvBitsPerByte;

  /// Markov estimate over the bit expansion (SP 800-90B 6.3.3), bits per byte.
  final double markovBitsPerByte;

  /// The claim the two cutoffs were calibrated for.
  final double floorBitsPerByte;

  /// Bytes the estimates and tests looked at.
  final int sampleBytes;

  /// Longest run of identical samples observed.
  final int longestRun;

  /// A run this long fails the repetition-count test; 0 when the engine
  /// predates the calibrated report.
  final int rctCutoff;

  /// Largest count seen in the adaptive-proportion window.
  final int maxWindowCount;

  /// A window count this high fails the adaptive-proportion test.
  final int aptCutoff;

  /// The adaptive-proportion window size.
  final int aptWindow;

  /// Repetition Count Test passed (SP 800-90B 4.4.1).
  final bool rctPassed;

  /// Adaptive Proportion Test passed (SP 800-90B 4.4.2).
  final bool aptPassed;

  /// One line per signal, as the engine explains it; empty on old engines.
  final String summary;

  /// Both statistical health tests passed. Still only a floor, not a warranty.
  bool get healthy => rctPassed && aptPassed;
}
