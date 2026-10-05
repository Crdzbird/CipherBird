part of '../cryptolib.dart';

/// SLH-DSA parameter set (FIPS 205) - stateless hash-based signatures.
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
