part of '../cipher_bird.dart';

/// The public half of a [SigningKey].
final class VerifyKey {
  VerifyKey._(this._lib, this.algorithm, this.publicKey);

  /// From public key bytes.
  factory VerifyKey.fromBytes(
    List<int> publicKey, {
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
    CipherBird? lib,
  }) => VerifyKey._(_easyLib(lib), algorithm, publicKey.u8);

  /// From a hex public key.
  factory VerifyKey.fromHex(
    String publicKeyHex, {
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
    CipherBird? lib,
  }) => VerifyKey.fromBytes(
    fromHex(publicKeyHex),
    algorithm: algorithm,
    lib: lib,
  );

  final CipherBird _lib;

  /// Which scheme this key belongs to.
  final SignatureAlgorithm algorithm;

  /// Public key bytes.
  final Uint8List publicKey;

  /// True if [signature] is a valid signature of [message] under this key.
  bool verify(List<int> message, List<int> signature) => switch (algorithm) {
    SignatureAlgorithm.hybrid => _lib.hybridSigVerify(
      message.u8,
      signature.u8,
      publicKey,
    ),
    _ => _lib.ed25519Verify(message.u8, signature.u8, publicKey),
  };

  /// Verify a string against a base64 signature from [SigningKey.signText].
  bool verifyText(String message, String signatureBase64) =>
      verify(message.bytes, signatureBase64.base64Bytes);

  /// Plug into a [CipherBirdRecipe]: `recipe.verifiedWith(key.scheme)`.
  SignatureScheme get scheme {
    if (algorithm == SignatureAlgorithm.hybrid) {
      return HybridSignature(publicKey: publicKey);
    }
    return Ed25519Signature(publicKey: publicKey);
  }
}
