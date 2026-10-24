part of '../../../cipher_bird.dart';

/// Steganography on bytes instead of files: the same engine entry points
/// over a scratch file, so a carrier picked in a browser or held in
/// memory works everywhere. The format names the carrier's container.
extension CipherBirdStegoBytes on CipherBird {
  /// Embed [payload] into [cover] and return the carrier bytes.
  Uint8List stegoEmbedBytes(
    Uint8List cover,
    MediaFormat format,
    Uint8List payload,
  ) => _withScratch((s) {
    final out = s.reserve(format.extension);
    stegoEmbed(s.put(format.extension, cover), payload, out);
    return s.take(out);
  });

  /// Extract the payload hidden in [stego].
  Uint8List stegoExtractBytes(Uint8List stego, MediaFormat format) =>
      _withScratch((s) => stegoExtract(s.put(format.extension, stego)));

  /// The payload capacity of [cover] in bytes.
  int stegoCapacityOf(Uint8List cover, MediaFormat format) =>
      _withScratch((s) => stegoCapacity(s.put(format.extension, cover)));

  /// Structural validity and true format of [bytes].
  StegoFileInspection stegoInspectBytes(Uint8List bytes, MediaFormat format) =>
      _withScratch((s) => stegoInspect(s.put(format.extension, bytes)));

  /// Probe [bytes] for hidden data; see [stegoDetectHidden] for the caveats.
  StegoHiddenDataReport stegoDetectHiddenBytes(
    Uint8List bytes,
    MediaFormat format,
  ) => _withScratch((s) => stegoDetectHidden(s.put(format.extension, bytes)));

  /// Digest of the decoded content of [bytes].
  Uint8List stegoContentDigestOf(Uint8List bytes, MediaFormat format) =>
      _withScratch((s) => stegoContentDigest(s.put(format.extension, bytes)));

  R _withScratch<R>(R Function(MediaScratch s) op) {
    final s = MediaScratch();
    try {
      return op(s);
    } finally {
      s.dispose();
    }
  }
}
