part of '../../cryptolib_ffi.dart';

/// Where a [CryptoRecipe]'s 32-byte root key comes from.
///
/// Subclass it for a hardware token, a KMS, a keyring unlock - anything that
/// can produce the same 32 bytes again when opening. The recipe refuses any
/// other length, so a weak source cannot silently narrow the key.
abstract class KeySource {
  const KeySource();

  /// Identifier recorded in the envelope header. Built-ins use 0–2; custom
  /// sources must use 128–255. Opening requires a source with the same id.
  int get id;

  /// Short name for `CryptoRecipe.describe`.
  String get label;

  /// Produce the root key. [salt] is fresh per envelope and stored in the
  /// header; [argon2Ops]/[argon2Memory] are the recipe's KDF cost, for sources
  /// that stretch a low-entropy input.
  Uint8List deriveRoot(
    CryptoLib lib,
    Uint8List salt,
    int argon2Ops,
    int argon2Memory,
  );
}
