part of '../cipher_bird.dart';

/// Noise XX secure channel (Noise_XX_25519_ChaChaPoly_SHA256).
extension type NoiseApi(CipherBird _l) {
  /// Create a Noise XX state from this side's X25519 keypair. Both sides must
  /// use the same [prologue].
  NoiseXX create({
    required bool initiator,
    required Uint8List staticPublic,
    required Uint8List staticSecret,
    Uint8List? prologue,
  }) => _l.noise(
    initiator: initiator,
    staticPublic: staticPublic,
    staticSecret: staticSecret,
    prologue: prologue,
  );
}
