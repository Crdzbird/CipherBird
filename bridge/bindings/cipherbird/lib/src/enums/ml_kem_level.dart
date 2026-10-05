part of '../cryptolib.dart';

/// ML-KEM parameter set (FIPS 203) - post-quantum key encapsulation.
///
/// [level768] is the recommended default and the one used by the library's
/// hybrid X25519+ML-KEM construction.
enum MlKemLevel {
  /// ML-KEM-512 - NIST security category 1.
  level512(0, 512, 1),

  /// ML-KEM-768 - NIST category 3. The recommended default.
  level768(1, 768, 3),

  /// ML-KEM-1024 - NIST category 5.
  level1024(2, 1024, 5);

  const MlKemLevel(this.value, this.bits, this.nistCategory);

  /// Wire value passed to the C ABI.
  final int value;

  /// Parameter-set size (512 / 768 / 1024).
  final int bits;

  /// NIST post-quantum security category.
  final int nistCategory;
}
