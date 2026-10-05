part of '../cipher_bird.dart';

/// Carriers that combine encryption with concealment, plus FEC.
extension type ComposedApi(CipherBird _l) {
  /// FEC-encode [data] under [scheme]. Apply before embedding when the carrier
  /// may be degraded in transit.
  Uint8List fecEncode(Uint8List data, FecScheme scheme) =>
      _l.fecEncode(data, scheme);

  /// FEC-decode [data], recovering [originalLength] bytes. [scheme] and
  /// [originalLength] must match what [fecEncode] was given.
  Uint8List fecDecode(Uint8List data, FecScheme scheme, int originalLength) =>
      _l.fecDecode(data, scheme, originalLength);

  /// Seal [plaintext] under a key derived from [keyMediaPath], hiding the
  /// result inside [coverPath] and writing it to [outputPath].
  ///
  /// Opening needs BOTH files: the key media (which never leaves your hands)
  /// and the carrier. The key file is conditioned deterministically, so the
  /// same file always yields the same key and nothing needs to be stored.
  void physicalSeal({
    required String keyMediaPath,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
  }) => _l.physicalSeal(
    keyMediaPath: keyMediaPath,
    plaintext: plaintext,
    coverPath: coverPath,
    outputPath: outputPath,
    aad: aad,
  );

  /// Recover a [physicalSeal]ed message. Requires the same key media file and
  /// the same [aad].
  Uint8List physicalOpen({
    required String keyMediaPath,
    required String stegoPath,
    Uint8List? aad,
  }) => _l.physicalOpen(
    keyMediaPath: keyMediaPath,
    stegoPath: stegoPath,
    aad: aad,
  );

  /// Seal [plaintext] behind two factors: the OPRF secret [oprfSecretSeed]
  /// (something you know) and the exact [referenceImagePath] (something you
  /// have). The ciphertext is hidden in [coverPath] -> [outputPath].
  ///
  /// Both factors are required to open; neither alone reveals anything.
  void imageFactorSeal({
    required Uint8List oprfSecretSeed,
    required String referenceImagePath,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
  }) => _l.imageFactorSeal(
    oprfSecretSeed: oprfSecretSeed,
    referenceImagePath: referenceImagePath,
    plaintext: plaintext,
    coverPath: coverPath,
    outputPath: outputPath,
    aad: aad,
  );

  /// Recover an [imageFactorSeal]ed message. Needs the same secret seed, the
  /// same reference image, and the same [aad].
  Uint8List imageFactorOpen({
    required Uint8List oprfSecretSeed,
    required String referenceImagePath,
    required String stegoPath,
    Uint8List? aad,
  }) => _l.imageFactorOpen(
    oprfSecretSeed: oprfSecretSeed,
    referenceImagePath: referenceImagePath,
    stegoPath: stegoPath,
    aad: aad,
  );
}
