part of '../../cryptolib.dart';

/// Carriers that combine encryption with concealment, plus FEC.
extension ComposedApiHpkeStego on ComposedApi {
  /// Seal [plaintext] to the recipient's HPKE public key [recipientPublic] and
  /// hide it in [coverPath] -> [outputPath].
  ///
  /// Returns the public KEM encapsulation (`enc`) - transmit it alongside the
  /// carrier, since the recipient needs it to open. Get keys from
  /// `hpkeKeygen()` / `hpkeDeriveKeyPair()`.
  Uint8List hpkeStegoSeal({
    required Uint8List recipientPublic,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
    Uint8List? info,
  }) => _l.hpkeStegoSeal(
    recipientPublic: recipientPublic,
    plaintext: plaintext,
    coverPath: coverPath,
    outputPath: outputPath,
    aad: aad,
    info: info,
  );

  /// Open an [hpkeStegoSeal]ed carrier with the recipient secret key and the
  /// `enc` value returned by the sealer. [aad] and [info] must match.
  Uint8List hpkeStegoOpen({
    required Uint8List recipientSecret,
    required Uint8List enc,
    required String stegoPath,
    Uint8List? aad,
    Uint8List? info,
  }) => _l.hpkeStegoOpen(
    recipientSecret: recipientSecret,
    enc: enc,
    stegoPath: stegoPath,
    aad: aad,
    info: info,
  );
}
