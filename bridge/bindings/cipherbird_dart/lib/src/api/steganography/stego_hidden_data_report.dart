part of '../../cipher_bird.dart';

/// Result of a heuristic probe for hidden data.
///
/// Read this as a signal, never a verdict: [cipherbirdPayload] is definitive
/// when true, but the statistical fields cannot prove that nothing is hidden.
final class StegoHiddenDataReport {
  const StegoHiddenDataReport({
    required this.cipherbirdPayload,
    required this.lsbChiSquare,
    required this.lsbEmbeddingLikelihood,
    required this.samplesAnalysed,
    required this.note,
  });

  /// An unkeyed CipherBird payload was actually recovered - definitive.
  final bool cipherbirdPayload;

  /// Raw chi-square statistic over least-significant bits.
  final double lsbChiSquare;

  /// Heuristic 0..1 likelihood of LSB embedding. High values warrant a look;
  /// low values prove nothing.
  final double lsbEmbeddingLikelihood;

  /// How many samples the analysis covered.
  final int samplesAnalysed;

  /// Caveat text describing the limits of this particular result.
  final String note;
}
