part of '../../cipher_bird.dart';

/// Encodings and derivation of a [SymmetricKey].
extension SymmetricKeyEncoding on SymmetricKey {
  /// A copy of the raw key bytes; wipe it when done.
  Uint8List get bytes => _secret.copy();

  /// The key as lowercase hex.
  String get hex => toHex(_key);

  /// The key as base64.
  String get base64 => base64Encode(_key);

  /// An independent sub-key for [purpose] (HKDF); different purposes never
  /// collide.
  SymmetricKey derive(String purpose) =>
      SymmetricKey._(_lib, _lib.hkdfDerive(_key, info: purpose.bytes));
}
