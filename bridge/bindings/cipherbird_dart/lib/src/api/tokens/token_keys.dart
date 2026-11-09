part of '../../cipher_bird.dart';

/// What [CipherBirdTokens.tokenKeygen] returns: the shared key of a local
/// format in [secretKey] with [publicKey] null, or both halves of a public
/// format's pair. [secretKey] is secret in both cases; [publicKey] is the
/// half to hand to verifiers.
final class TokenKeys {
  /// Builds the pair; the engine fills it through [CipherBirdTokens.tokenKeygen].
  const TokenKeys(this.secretKey, this.publicKey);

  /// The shared key (local) or the signing half (public).
  final Uint8List secretKey;

  /// The verifying half of a public format's pair; null for a local one.
  final Uint8List? publicKey;

  /// Whether this is a signing pair rather than a shared key.
  bool get isPair => publicKey != null;
}
