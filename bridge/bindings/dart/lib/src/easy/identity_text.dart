part of '../../cryptolib_ffi.dart';

/// String convenience on the Flagship/Fortress [Identity].
extension IdentityText on Identity {
  /// Seal a string for the holder of [to]; returns base64.
  String sealText(
    String plaintext, {
    required Uint8List to,
    String? aad,
    String? purpose,
  }) =>
      seal(
        plaintext.bytes,
        to,
        aad: aad?.bytes,
        purpose: purpose?.bytes,
      ).base64;

  /// Open a base64 envelope from the holder of [from].
  String openText(
    String envelopeBase64, {
    required Uint8List from,
    String? aad,
    String? purpose,
  }) =>
      open(
        envelopeBase64.base64Bytes,
        from,
        aad: aad?.bytes,
        purpose: purpose?.bytes,
      ).text;
}
