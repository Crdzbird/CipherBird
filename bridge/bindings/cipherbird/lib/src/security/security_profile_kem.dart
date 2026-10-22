part of '../cipher_bird.dart';

/// The standards-track choices every [SecurityProfile] makes (assessment r2,
/// M4 and M8): no profile falls back to a classical-only KEM.
extension SecurityProfileKem on SecurityProfile {
  /// HPKE KEM: X-Wing (ML-KEM-768 + X25519) at every level.
  HpkeKem get hpkeKem => HpkeKem.xWing;

  /// Suite v2 cipher suite: X-Wing with the hybrid signature at every level.
  Suite2Id get suite2 => Suite2Id.xWingSig;
}
