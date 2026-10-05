part of '../cipher_bird.dart';

/// Random bytes and explicitly-seeded generators.
extension type RngApi(CipherBird _l) {
  /// [count] cryptographically-secure random bytes straight from the OS CSPRNG.
  ///
  /// This is the right default for key generation. Reach for [drbg] or
  /// [fortuna] only when you need reproducibility or your own entropy sources.
  Uint8List bytes(int count) => _l.randomBytes(count);

  /// Instantiate an HMAC-DRBG from a caller-supplied seed.
  ///
  /// [entropy] should carry at least 32 bytes of real entropy. [nonce] and
  /// [personalization] provide domain separation so two DRBGs seeded from the
  /// same entropy still produce different streams.
  Drbg drbg(
    Uint8List entropy, {
    Uint8List? nonce,
    Uint8List? personalization,
  }) => _l.drbg(entropy, nonce: nonce, personalization: personalization);

  /// Create a new, unseeded Fortuna pool. Feed it via [Fortuna.addEntropy]
  /// before generating.
  Fortuna fortuna() => _l.fortuna();
}
