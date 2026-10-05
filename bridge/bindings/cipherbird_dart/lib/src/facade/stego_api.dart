part of '../cipher_bird.dart';

/// Steganographic embedding, extraction and carrier diagnostics.
extension type StegoApi(CipherBird _l) {
  /// Embed raw bytes into a media file.
  void embed(String coverPath, Uint8List payload, String outputPath) =>
      _l.stegoEmbed(coverPath, payload, outputPath);

  /// Extract raw bytes from a stego media file.
  Uint8List extract(String stegoPath) => _l.stegoExtract(stegoPath);

  /// Get the steganographic capacity of a cover file (in bytes).
  int capacity(String coverPath) => _l.stegoCapacity(coverPath);

  /// Embed [payload] into [coverPath] -> [outputPath], permuting placement under
  /// [key]. Without the key an extractor cannot locate the bits.
  ///
  /// This hides *where* the data is; it does not encrypt it. Use
  /// [embedEncrypted] when the payload itself must stay confidential.
  void embedKeyed(
    String coverPath,
    Uint8List payload,
    String outputPath,
    Uint8List key,
  ) => _l.stegoEmbedKeyed(coverPath, payload, outputPath, key);

  /// Extract a [embedKeyed] payload. Throws on the wrong key.
  Uint8List extractKeyed(String stegoPath, Uint8List key) =>
      _l.stegoExtractKeyed(stegoPath, key);

  /// Authenticated-encrypt [plaintext] under [masterKey], then hide the
  /// ciphertext in [coverPath] -> [outputPath].
  ///
  /// This is the one to reach for by default: confidentiality rests on the key,
  /// with the carrier adding concealment on top.
  void embedEncrypted(
    String coverPath,
    Uint8List plaintext,
    String outputPath,
    Uint8List masterKey,
  ) => _l.stegoEmbedEncrypted(coverPath, plaintext, outputPath, masterKey);

  /// Extract and decrypt a [embedEncrypted] payload. Fails closed on a
  /// wrong key or a tampered carrier.
  Uint8List extractDecrypt(String stegoPath, Uint8List masterKey) =>
      _l.stegoExtractDecrypt(stegoPath, masterKey);

  /// Inspect a media file's structural validity and true format.
  StegoFileInspection inspect(String path) => _l.stegoInspect(path);

  /// Probe [path] for hidden data.
  ///
  /// A positive [StegoHiddenDataReport.cipherbirdPayload] is conclusive; the
  /// statistical fields are heuristics that can suggest embedding but can never
  /// establish its absence.
  StegoHiddenDataReport detectHidden(String path) => _l.stegoDetectHidden(path);

  /// Digest of a carrier's *decoded content* rather than its file bytes.
  ///
  /// Stable across re-encodings that preserve the samples/pixels, so it
  /// identifies the underlying media even when the container changes.
  Uint8List contentDigest(String path) => _l.stegoContentDigest(path);
}
