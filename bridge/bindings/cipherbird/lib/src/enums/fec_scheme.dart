part of '../cryptolib.dart';

/// Forward-error-correction scheme applied to a stego payload.
///
/// Trades carrier capacity for tolerance of bounded bit errors - useful when a
/// carrier may be recompressed or resampled in transit. Classic codes, no new
/// cryptography.
enum FecScheme {
  /// No redundancy. Full capacity, no error tolerance.
  none(0),

  /// Each bit repeated 3x; corrects 1 error per triple. ~1/3 capacity.
  repetition3(1),

  /// Each bit repeated 5x; corrects 2 errors per group. ~1/5 capacity.
  repetition5(2),

  /// Hamming(7,4): corrects 1 error per 7-bit block. ~4/7 capacity.
  hamming74(3);

  const FecScheme(this.value);

  /// Wire value passed to the C ABI.
  final int value;
}
