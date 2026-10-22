part of '../cipher_bird.dart';

/// Hash functions the FIPS profile exposes.
enum FipsHash {
  /// SHA-256.
  sha256(0),

  /// SHA-384.
  sha384(1),

  /// SHA-512.
  sha512(2),

  /// SHA3-256.
  sha3_256(3);

  const FipsHash(this.value);

  /// C ABI hash id.
  final int value;
}
