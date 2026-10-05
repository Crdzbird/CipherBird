part of '../cryptolib.dart';

/// HPKE AEAD selector. Values are the RFC 9180 registry codepoints.
enum HpkeAead {
  /// AES-128-GCM.
  aes128Gcm(1),

  /// AES-256-GCM.
  aes256Gcm(2),

  /// ChaCha20-Poly1305.
  chaCha20Poly1305(3),

  /// Export-only: derive secrets, no message encryption.
  exportOnly(0xFFFF);

  const HpkeAead(this.value);

  /// RFC 9180 AEAD identifier.
  final int value;
}
