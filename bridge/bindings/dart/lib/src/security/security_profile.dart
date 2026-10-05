part of '../../cryptolib_ffi.dart';

/// A coherent set of algorithm parameters, from ordinary to maximal.
///
/// Every field moves together, so you cannot accidentally pair a maximal KEM
/// with an interactive-cost KDF. Reach for [maximum] when the data outlives the
/// threat model you can predict.
enum SecurityProfile {
  /// Sound modern defaults. Fast enough for interactive use.
  balanced,

  /// Stronger parameters and a two-cipher cascade. Noticeably slower to unlock.
  high,

  /// The strongest option the library offers at every single choice: category-5
  /// post-quantum parameter sets, the triple-family sealed tier, a
  /// three-layer cascade ending in a key-committing AEAD, and a memory-hard KDF
  /// tuned well past interactive comfort.
  maximum;

  /// ML-KEM parameter set for this profile.
  MlKemLevel get mlKem => switch (this) {
        SecurityProfile.balanced => MlKemLevel.level768,
        SecurityProfile.high => MlKemLevel.level768,
        SecurityProfile.maximum => MlKemLevel.level1024,
      };

  /// ML-DSA parameter set for this profile.
  MlDsaLevel get mlDsa => switch (this) {
        SecurityProfile.balanced => MlDsaLevel.level65,
        SecurityProfile.high => MlDsaLevel.level65,
        SecurityProfile.maximum => MlDsaLevel.level87,
      };

  /// SLH-DSA parameter set. [maximum] takes the small-signature variant: it
  /// signs more slowly but keeps signatures compact, and hash-based security is
  /// the point of using it at all.
  SlhDsaLevel get slhDsa => switch (this) {
        SecurityProfile.balanced => SlhDsaLevel.fast128,
        SecurityProfile.high => SlhDsaLevel.fast192,
        SecurityProfile.maximum => SlhDsaLevel.small256,
      };

  /// Hash family for SLH-DSA.
  SlhDsaHash get slhDsaHash =>
      this == SecurityProfile.maximum ? SlhDsaHash.shake : SlhDsaHash.sha2;

  /// Sealed-messaging tier. [maximum] uses the triple-family Fortress tier.
  SealedTier get sealedTier => this == SecurityProfile.maximum
      ? SealedTier.fortress
      : SealedTier.flagship;

  /// HPKE KDF.
  HpkeKdf get hpkeKdf =>
      this == SecurityProfile.maximum ? HpkeKdf.sha512 : HpkeKdf.sha256;

  /// HPKE AEAD.
  HpkeAead get hpkeAead => HpkeAead.chaCha20Poly1305;

  /// Argon2id cost preset for vault and keyring slots.
  KdfPreset get kdfPreset => this == SecurityProfile.balanced
      ? KdfPreset.interactive
      : KdfPreset.sensitive;

  /// Argon2id iteration count used by [CryptoRecipe].
  int get argon2Ops => switch (this) {
        SecurityProfile.balanced => 2,
        SecurityProfile.high => 3,
        SecurityProfile.maximum => 4,
      };

  /// Argon2id memory cost in bytes used by [CryptoRecipe].
  ///
  /// Memory is what actually costs an attacker; raise it as far as the slowest
  /// device you must support can bear.
  int get argon2Memory => switch (this) {
        SecurityProfile.balanced => 64 * 1024 * 1024,
        SecurityProfile.high => 256 * 1024 * 1024,
        SecurityProfile.maximum => 512 * 1024 * 1024,
      };

  /// The AEAD cascade this profile applies, innermost first.
  ///
  /// Independent cipher families mean a break of one does not open the
  /// envelope, and the key-committing outer layer closes partitioning-oracle
  /// and Invisible-Salamanders style attacks.
  List<ProtectionLayer> get cascade => switch (this) {
        SecurityProfile.balanced => const [ProtectionLayer.xchacha20Poly1305],
        SecurityProfile.high => const [
            ProtectionLayer.xchacha20Poly1305,
            ProtectionLayer.aes256Gcm,
          ],
        SecurityProfile.maximum => const [
            ProtectionLayer.xchacha20Poly1305,
            ProtectionLayer.aes256Gcm,
            ProtectionLayer.committing,
          ],
      };
}
