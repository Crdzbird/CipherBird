part of '../cipher_bird.dart';

/// HPKE KDF selector. Values are the RFC 9180 registry codepoints.
enum HpkeKdf {
  /// HKDF-SHA256.
  sha256(1),

  /// HKDF-SHA512.
  sha512(3);

  const HpkeKdf(this.value);

  /// RFC 9180 KDF identifier.
  final int value;
}
