part of '../../cryptolib_ffi.dart';

/// A signing key pair: Ed25519 by default, or the post-quantum hybrid
/// (Ed25519 + ML-DSA-65, a forgery needs breaking both).
///
/// ```dart
/// final key = SigningKey.generate();
/// final sig = key.signText('release 4.1.0');
/// final ok = key.verifyKey.verifyText('release 4.1.0', sig);
/// ```
final class SigningKey {
  SigningKey._(this._lib, this.algorithm, this._pair);

  /// A fresh key pair.
  factory SigningKey.generate({
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
    CryptoLib? lib,
  }) {
    final l = _easyLib(lib);
    return SigningKey._(
        l,
        algorithm,
        switch (algorithm) {
          SignatureAlgorithm.ed25519 => l.ed25519Keygen(),
          SignatureAlgorithm.hybrid => l.hybridSigKeygen(),
          SignatureAlgorithm.none => throw ArgumentError.value(
              algorithm,
              'algorithm',
              'pick a real algorithm',
            ),
        });
  }

  /// Wrap existing key bytes (e.g. loaded from secure storage).
  factory SigningKey.fromBytes({
    required List<int> secretKey,
    required List<int> publicKey,
    SignatureAlgorithm algorithm = SignatureAlgorithm.ed25519,
    CryptoLib? lib,
  }) =>
      SigningKey._(
        _easyLib(lib),
        algorithm,
        KeyPairResult(publicKey: publicKey.u8, secretKey: secretKey.u8),
      );

  final CryptoLib _lib;

  /// Which scheme this key belongs to.
  final SignatureAlgorithm algorithm;
  final KeyPairResult _pair;

  /// Public key bytes - share freely.
  Uint8List get publicKey => _pair.publicKey;

  /// Secret key bytes - never leave the device.
  Uint8List get secretKey => _pair.secretKey;

  /// The verification half, safe to hand to anyone.
  VerifyKey get verifyKey =>
      VerifyKey.fromBytes(publicKey, algorithm: algorithm, lib: _lib);

  /// Sign [message]; returns the detached signature.
  Uint8List sign(List<int> message) => switch (algorithm) {
        SignatureAlgorithm.hybrid => _lib.hybridSigSign(message.u8, secretKey),
        _ => _lib.ed25519Sign(message.u8, secretKey),
      };

  /// Sign a string; returns the signature as base64.
  String signText(String message) => sign(message.bytes).base64;

  /// Verify with this key's own public half.
  bool verify(List<int> message, List<int> signature) =>
      verifyKey.verify(message, signature);

  /// Plug into a [CryptoRecipe]: `recipe.signedWith(key.scheme)`.
  SignatureScheme get scheme {
    if (algorithm == SignatureAlgorithm.hybrid) {
      return HybridSignature(secretKey: secretKey, publicKey: publicKey);
    }
    return Ed25519Signature(secretKey: secretKey, publicKey: publicKey);
  }
}
