part of '../cipher_bird.dart';

/// Suite v2 cipher suite ids.
enum Suite2Id {
  /// X-Wing with the Ed25519 + ML-DSA-65 signature: every profile.
  xWingSig(0x11),

  /// The library-native X25519 + ML-KEM-768 combiner: full profile only.
  hybridSig(0x12);

  const Suite2Id(this.value);

  /// Wire suite id.
  final int value;
}
