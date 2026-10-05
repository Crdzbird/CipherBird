part of '../../cryptolib_ffi.dart';

/// Hex views of a raw key pair.
extension KeyPairText on KeyPairResult {
  /// Public key as lowercase hex.
  String get publicHex => toHex(publicKey);

  /// Secret key as lowercase hex. Handle with care.
  String get secretHex => toHex(secretKey);
}
