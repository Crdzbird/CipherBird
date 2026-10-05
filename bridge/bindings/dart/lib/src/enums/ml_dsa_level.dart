part of '../../cryptolib_ffi.dart';

/// ML-DSA parameter set (FIPS 204) - post-quantum digital signatures.
///
/// [level65] is the recommended default and the one used by the library's
/// hybrid Ed25519+ML-DSA construction.
enum MlDsaLevel {
  /// ML-DSA-44 - NIST security category 2.
  level44(0, 44, 2),

  /// ML-DSA-65 - NIST category 3. The recommended default.
  level65(1, 65, 3),

  /// ML-DSA-87 - NIST category 5.
  level87(2, 87, 5);

  const MlDsaLevel(this.value, this.parameterSet, this.nistCategory);

  /// Wire value passed to the C ABI.
  final int value;

  /// Parameter-set number (44 / 65 / 87).
  final int parameterSet;

  /// NIST post-quantum security category.
  final int nistCategory;
}
