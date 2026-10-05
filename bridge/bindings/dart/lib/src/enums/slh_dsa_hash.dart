part of '../../cryptolib_ffi.dart';

/// Hash family underlying SLH-DSA.
enum SlhDsaHash {
  /// SHA-2 family.
  sha2(0),

  /// SHAKE (SHA-3) family.
  shake(1);

  const SlhDsaHash(this.value);

  /// Wire value passed to the C ABI.
  final int value;
}
