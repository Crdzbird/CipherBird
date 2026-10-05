part of '../cryptolib.dart';

/// How a [CryptoRecipe] signs and verifies the plaintext.
///
/// Subclass it for another signature algorithm. A scheme that only holds a
/// public key should throw from [sign]. The signature is always applied to the
/// plaintext BEFORE encryption, so it travels confidentially.
abstract class SignatureScheme {
  const SignatureScheme();

  /// Identifier recorded in the envelope header. Built-ins use 1–2; custom
  /// schemes must use 128–255. Verification requires a scheme with the same id.
  int get id;

  /// Short name for `CryptoRecipe.describe`.
  String get label;

  /// Sign [message].
  Uint8List sign(CryptoLib lib, Uint8List message);

  /// Verify [signature] over [message]. Must return false, never throw
  /// through, on a bad signature.
  bool verify(CryptoLib lib, Uint8List message, Uint8List signature);
}
