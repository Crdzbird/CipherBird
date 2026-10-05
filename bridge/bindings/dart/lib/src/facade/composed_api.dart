part of '../../cryptolib_ffi.dart';

/// Carriers that combine encryption with concealment, plus FEC.
extension type ComposedApi(CryptoLib _l) {
  /// Two-factor "the photo is the key" seal: [keyMediaPath] is conditioned into
  /// AEAD + stego keys; [plaintext] (binding [aad]) is sealed and hidden in a
  /// SEPARATE [coverPath], written to [outputPath]. Both files are required to open.
  void physicalSeal(String keyMediaPath, Uint8List plaintext, Uint8List aad,
          String coverPath, String outputPath) =>
      _l.physicalSeal(keyMediaPath, plaintext, aad, coverPath, outputPath);

  /// Recover a [physicalSeal] message: reconstruct keys from [keyMediaPath],
  /// extract from [stegoPath], and AEAD-open under [aad].
  Uint8List physicalOpen(
          String keyMediaPath, Uint8List aad, String stegoPath) =>
      _l.physicalOpen(keyMediaPath, aad, stegoPath);

  /// Forward error correction encode. scheme: 0=None, 1=Repetition-3,
  /// 2=Repetition-5, 3=Hamming(7,4). Trades capacity for bit-error recovery.
  Uint8List fecEncode(Uint8List data, FecScheme scheme) =>
      _l.fecEncode(data, scheme);

  /// Forward error correction decode: recover [originalLen] bytes from [data],
  /// correcting within the scheme's capability. Throws if [data] is too short.
  Uint8List fecDecode(Uint8List data, FecScheme scheme, int originalLen) =>
      _l.fecDecode(data, scheme, originalLen);

  /// Seal [plaintext] (binding [aad]) under OPRF([oprfSecretSeed], the reference
  /// image), hiding the ciphertext in [coverPath] -> [outputPath]. Two factors to
  /// open: the OPRF secret AND the exact reference image.
  void imageFactorSeal(
          Uint8List oprfSecretSeed,
          String referenceImagePath,
          Uint8List plaintext,
          Uint8List aad,
          String coverPath,
          String outputPath) =>
      _l.imageFactorSeal(oprfSecretSeed, referenceImagePath, plaintext, aad,
          coverPath, outputPath);

  /// Recover an [imageFactorSeal] message.
  Uint8List imageFactorOpen(Uint8List oprfSecretSeed, String referenceImagePath,
          Uint8List aad, String stegoPath) =>
      _l.imageFactorOpen(oprfSecretSeed, referenceImagePath, aad, stegoPath);

  /// Seal [plaintext] to recipient public key [pkR], hiding the ciphertext in
  /// [coverPath] -> [outputPath]. Returns the PUBLIC KEM encapsulation `enc`.
  Uint8List hpkeStegoSeal(Uint8List pkR, Uint8List plaintext, Uint8List aad,
          Uint8List info, String coverPath, String outputPath) =>
      _l.hpkeStegoSeal(pkR, plaintext, aad, info, coverPath, outputPath);

  /// Recover an [hpkeStegoSeal] message with recipient secret [skR] and `enc`.
  Uint8List hpkeStegoOpen(Uint8List skR, Uint8List enc, Uint8List aad,
          Uint8List info, String stegoPath) =>
      _l.hpkeStegoOpen(skR, enc, aad, info, stegoPath);
}
