part of '../cryptolib_ffi.dart';

// ── Algorithm selectors ──────────────────────────────────────────────────────
// Every parameter that used to be a bare `int` (a wire value copied out of a C
// header comment) is one of these. They carry their own wire encoding, so a
// wrong constant can no longer be passed silently.

/// ML-KEM parameter set (FIPS 203) — post-quantum key encapsulation.
///
/// [level768] is the recommended default and the one used by the library's
/// hybrid X25519+ML-KEM construction.
enum MlKemLevel {
  /// ML-KEM-512 — NIST security category 1.
  level512(0, 512, 1),

  /// ML-KEM-768 — NIST category 3. The recommended default.
  level768(1, 768, 3),

  /// ML-KEM-1024 — NIST category 5.
  level1024(2, 1024, 5);

  const MlKemLevel(this.value, this.bits, this.nistCategory);

  /// Wire value passed to the C ABI.
  final int value;

  /// Parameter-set size (512 / 768 / 1024).
  final int bits;

  /// NIST post-quantum security category.
  final int nistCategory;
}

/// ML-DSA parameter set (FIPS 204) — post-quantum digital signatures.
///
/// [level65] is the recommended default and the one used by the library's
/// hybrid Ed25519+ML-DSA construction.
enum MlDsaLevel {
  /// ML-DSA-44 — NIST security category 2.
  level44(0, 44, 2),

  /// ML-DSA-65 — NIST category 3. The recommended default.
  level65(1, 65, 3),

  /// ML-DSA-87 — NIST category 5.
  level87(2, 87, 5);

  const MlDsaLevel(this.value, this.parameterSet, this.nistCategory);

  /// Wire value passed to the C ABI.
  final int value;

  /// Parameter-set number (44 / 65 / 87).
  final int parameterSet;

  /// NIST post-quantum security category.
  final int nistCategory;
}

/// SLH-DSA parameter set (FIPS 205) — stateless hash-based signatures.
///
/// Each security level comes in two variants: `small` produces compact
/// signatures at the cost of slower signing, `fast` signs quicker but emits
/// larger signatures. Hash-based security rests only on the hash function, which
/// is why this family backstops the lattice schemes in the triple-signature
/// construction.
enum SlhDsaLevel {
  /// 128-bit, small signatures / slower signing.
  small128(0, 128, false),

  /// 128-bit, faster signing / larger signatures.
  fast128(1, 128, true),

  /// 192-bit, small signatures / slower signing.
  small192(2, 192, false),

  /// 192-bit, faster signing / larger signatures.
  fast192(3, 192, true),

  /// 256-bit, small signatures / slower signing.
  small256(4, 256, false),

  /// 256-bit, faster signing / larger signatures.
  fast256(5, 256, true);

  const SlhDsaLevel(this.value, this.bits, this.fastVariant);

  /// Wire value passed to the C ABI.
  final int value;

  /// Security level in bits (128 / 192 / 256).
  final int bits;

  /// `true` for the fast-signing variant, `false` for the small-signature one.
  final bool fastVariant;
}

/// Hash family underlying SLH-DSA.
enum SlhDsaHash {
  /// SHA-2 family.
  sha2(0),

  /// SHAKE (SHA-3) family.
  shake(1);

  const SlhDsaHash(this.value);

  /// Wire value passed to the C ABI.
  final int value;
}

// ── HPKE (RFC 9180) ciphersuite selectors ────────────────────────────────────

/// HPKE KDF selector. Values are the RFC 9180 registry codepoints.
enum HpkeKdf {
  /// HKDF-SHA256.
  sha256(1),

  /// HKDF-SHA512.
  sha512(3);

  const HpkeKdf(this.value);

  /// RFC 9180 KDF identifier.
  final int value;
}

/// HPKE AEAD selector. Values are the RFC 9180 registry codepoints.
enum HpkeAead {
  /// AES-128-GCM.
  aes128Gcm(1),

  /// AES-256-GCM.
  aes256Gcm(2),

  /// ChaCha20-Poly1305.
  chaCha20Poly1305(3),

  /// Export-only: derive secrets, no message encryption.
  exportOnly(0xFFFF);

  const HpkeAead(this.value);

  /// RFC 9180 AEAD identifier.
  final int value;
}

/// HPKE mode. Determines which of sender authentication and pre-shared-key
/// authentication are in play.
enum HpkeMode {
  /// Recipient authentication only.
  base(0),

  /// Adds a pre-shared key.
  psk(1),

  /// Adds sender authentication via a static sender key.
  auth(2),

  /// Both a pre-shared key and sender authentication.
  authPsk(3);

  const HpkeMode(this.value);

  /// RFC 9180 mode identifier.
  final int value;

  /// This mode requires a `psk` and `pskId`.
  bool get requiresPsk => this == HpkeMode.psk || this == HpkeMode.authPsk;

  /// This mode requires a static sender key (`skS` when sealing, `pkS` when
  /// opening).
  bool get requiresSenderKey => this == HpkeMode.auth || this == HpkeMode.authPsk;
}

// ── Steganography / carrier selectors ────────────────────────────────────────

/// Media container format inferred from a file's actual bytes (not its
/// extension). Returned by [CryptoLibStegoAdvanced.stegoInspect].
enum MediaFormat {
  ppmImage(0),
  wavAudio(1),
  crvfVideo(2),
  bmpImage(3),
  pngImage(4),
  flacAudio(5),
  aviVideo(6),
  gifImage(7),
  jpegImage(8),
  mp3Audio(9),
  mp4Video(10),

  /// Content did not match any supported carrier format.
  unknown(0xFF);

  const MediaFormat(this.value);

  /// Wire value used by the C ABI.
  final int value;

  /// Map a raw C ABI value, falling back to [unknown].
  static MediaFormat fromValue(int v) =>
      MediaFormat.values.firstWhere((f) => f.value == v, orElse: () => MediaFormat.unknown);
}

/// Forward-error-correction scheme applied to a stego payload.
///
/// Trades carrier capacity for tolerance of bounded bit errors — useful when a
/// carrier may be recompressed or resampled in transit. Classic codes, no new
/// cryptography.
enum FecScheme {
  /// No redundancy. Full capacity, no error tolerance.
  none(0),

  /// Each bit repeated 3x; corrects 1 error per triple. ~1/3 capacity.
  repetition3(1),

  /// Each bit repeated 5x; corrects 2 errors per group. ~1/5 capacity.
  repetition5(2),

  /// Hamming(7,4): corrects 1 error per 7-bit block. ~4/7 capacity.
  hamming74(3);

  const FecScheme(this.value);

  /// Wire value passed to the C ABI.
  final int value;
}

// ── Key-derivation cost ──────────────────────────────────────────────────────

/// Argon2id cost preset used when a passphrase is stretched into a key.
///
/// The cost is a deliberate trade: every increase multiplies an attacker's
/// guessing cost by the same factor it adds to your own unlock time. Pick the
/// slowest setting your UX can absorb.
enum KdfPreset {
  /// Tuned for interactive unlock (~fast enough for a login prompt).
  interactive(0),

  /// Substantially more memory and time. Use for keys guarding data at rest,
  /// where an extra second of unlock is worth the attacker's extra magnitude.
  sensitive(1);

  const KdfPreset(this.value);

  /// Wire value passed to the C ABI.
  final int value;
}
