part of '../cryptolib.dart';

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
