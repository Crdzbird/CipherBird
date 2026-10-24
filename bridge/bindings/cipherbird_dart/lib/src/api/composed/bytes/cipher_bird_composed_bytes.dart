part of '../../../cipher_bird.dart';

/// The composed seals on bytes: key media, reference images and carriers
/// held in memory instead of files.
extension CipherBirdComposedBytes on CipherBird {
  /// [physicalSeal] on bytes; returns the carrier.
  Uint8List physicalSealBytes({
    required Uint8List keyMedia,
    required MediaFormat keyMediaFormat,
    required Uint8List plaintext,
    required Uint8List cover,
    required MediaFormat coverFormat,
    Uint8List? aad,
  }) => _withScratch((s) {
    final out = s.reserve(coverFormat.extension);
    physicalSeal(
      keyMediaPath: s.put(keyMediaFormat.extension, keyMedia),
      plaintext: plaintext,
      coverPath: s.put(coverFormat.extension, cover),
      outputPath: out,
      aad: aad,
    );
    return s.take(out);
  });

  /// [physicalOpen] on bytes.
  Uint8List physicalOpenBytes({
    required Uint8List keyMedia,
    required MediaFormat keyMediaFormat,
    required Uint8List stego,
    required MediaFormat stegoFormat,
    Uint8List? aad,
  }) => _withScratch(
    (s) => physicalOpen(
      keyMediaPath: s.put(keyMediaFormat.extension, keyMedia),
      stegoPath: s.put(stegoFormat.extension, stego),
      aad: aad,
    ),
  );

  /// [hpkeStegoSeal] on bytes; returns the encapsulation and the carrier.
  ({Uint8List enc, Uint8List carrier}) hpkeStegoSealBytes({
    required Uint8List recipientPublic,
    required Uint8List plaintext,
    required Uint8List cover,
    required MediaFormat coverFormat,
    Uint8List? aad,
    Uint8List? info,
  }) => _withScratch((s) {
    final out = s.reserve(coverFormat.extension);
    final enc = hpkeStegoSeal(
      recipientPublic: recipientPublic,
      plaintext: plaintext,
      coverPath: s.put(coverFormat.extension, cover),
      outputPath: out,
      aad: aad,
      info: info,
    );
    return (enc: enc, carrier: s.take(out));
  });

  /// [hpkeStegoOpen] on bytes.
  Uint8List hpkeStegoOpenBytes({
    required Uint8List recipientSecret,
    required Uint8List enc,
    required Uint8List stego,
    required MediaFormat stegoFormat,
    Uint8List? aad,
    Uint8List? info,
  }) => _withScratch(
    (s) => hpkeStegoOpen(
      recipientSecret: recipientSecret,
      enc: enc,
      stegoPath: s.put(stegoFormat.extension, stego),
      aad: aad,
      info: info,
    ),
  );
}
