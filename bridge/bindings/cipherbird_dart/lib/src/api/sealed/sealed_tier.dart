part of '../../cryptolib.dart';

/// Assurance tier for Flagship/Fortress sealed messaging.
///
/// [flagship] is the default: hybrid-PQ confidential and authentic.
/// [fortress] adds a third independent family to each leg, so no single
/// cryptanalytic break compromises the envelope.
enum SealedTier {
  /// X25519 + sntrup761 KEM, Ed25519 + ML-DSA-65 signature.
  flagship(0, 1),

  /// Adds ML-KEM-768 to the KEM and SLH-DSA to the signature.
  fortress(1, 2);

  const SealedTier(this.value, this.suiteId);

  /// Wire value passed to the C ABI (0 / 1).
  final int value;

  /// Suite identifier as reported inside a sealed envelope (1 / 2).
  final int suiteId;

  /// Map an envelope's reported suite id back to a tier.
  static SealedTier fromSuiteId(int id) => SealedTier.values.firstWhere(
    (t) => t.suiteId == id,
    orElse: () => SealedTier.flagship,
  );
}
