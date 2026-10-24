part of '../../../cipher_bird.dart';

/// The image-factor seal on bytes.
extension CipherBirdImageFactorBytes on CipherBird {
  /// [imageFactorSeal] on bytes; returns the carrier.
  Uint8List imageFactorSealBytes({
    required Uint8List oprfSecretSeed,
    required Uint8List referenceImage,
    required MediaFormat referenceFormat,
    required Uint8List plaintext,
    required Uint8List cover,
    required MediaFormat coverFormat,
    Uint8List? aad,
  }) => _withScratch((s) {
    final out = s.reserve(coverFormat.extension);
    imageFactorSeal(
      oprfSecretSeed: oprfSecretSeed,
      referenceImagePath: s.put(referenceFormat.extension, referenceImage),
      plaintext: plaintext,
      coverPath: s.put(coverFormat.extension, cover),
      outputPath: out,
      aad: aad,
    );
    return s.take(out);
  });

  /// [imageFactorOpen] on bytes.
  Uint8List imageFactorOpenBytes({
    required Uint8List oprfSecretSeed,
    required Uint8List referenceImage,
    required MediaFormat referenceFormat,
    required Uint8List stego,
    required MediaFormat stegoFormat,
    Uint8List? aad,
  }) => _withScratch(
    (s) => imageFactorOpen(
      oprfSecretSeed: oprfSecretSeed,
      referenceImagePath: s.put(referenceFormat.extension, referenceImage),
      stegoPath: s.put(stegoFormat.extension, stego),
      aad: aad,
    ),
  );
}
