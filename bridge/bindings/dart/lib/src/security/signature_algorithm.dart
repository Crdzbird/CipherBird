part of '../../cryptolib_ffi.dart';

/// Built-in signature algorithms, for the `CryptoRecipe.signedBy` shorthand.
enum SignatureAlgorithm {
  /// No signature. The AEAD still guarantees integrity, but not who sent it.
  none(0),

  /// Ed25519.
  ed25519(1),

  /// Ed25519 + ML-DSA-65. A forgery needs breaking both families.
  hybrid(2);

  const SignatureAlgorithm(this.id);

  /// Identifier recorded in the envelope header.
  final int id;
}
