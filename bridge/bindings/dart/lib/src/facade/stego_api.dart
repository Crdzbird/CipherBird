part of '../../cryptolib_ffi.dart';

/// Steganographic embedding, extraction and carrier diagnostics.
extension type StegoApi(CryptoLib _l) {
  /// Embed raw bytes into a media file.
  void embed(String coverPath, Uint8List payload, String outputPath) =>
      _l.stegoEmbed(coverPath, payload, outputPath);

  /// Extract raw bytes from a stego media file.
  Uint8List extract(String stegoPath) => _l.stegoExtract(stegoPath);

  /// Get the steganographic capacity of a cover file (in bytes).
  int capacity(String coverPath) => _l.stegoCapacity(coverPath);

  /// Embed with key-derived whitening (and, for .ppm, block permutation) so no
  /// 'CSTG' signature survives. The same key must be used to [stegoExtractKeyed].
  void embedKeyed(String coverPath, Uint8List payload, String outputPath,
          Uint8List key) =>
      _l.stegoEmbedKeyed(coverPath, payload, outputPath, key);

  /// Extract a keyed-embedded payload. A wrong key fails fast.
  Uint8List extractKeyed(String stegoPath, Uint8List key) =>
      _l.stegoExtractKeyed(stegoPath, key);

  /// AEAD-seal [plaintext] under a key derived from [masterKey], then hide the
  /// ciphertext (always-encrypt: no cleartext in the carrier). .ppm carrier.
  void embedEncrypted(String coverPath, Uint8List plaintext, String outputPath,
          Uint8List masterKey) =>
      _l.stegoEmbedEncrypted(coverPath, plaintext, outputPath, masterKey);

  /// Extract and AEAD-open a carrier written by [stegoEmbedEncrypted]. Wrong key
  /// or tampering throws.
  Uint8List extractDecrypt(String stegoPath, Uint8List masterKey) =>
      _l.stegoExtractDecrypt(stegoPath, masterKey);

  /// Inspect a media file's structural validity and whether its content matches
  /// its extension.
  StegoFileInspection inspect(String path) => _l.stegoInspect(path);

  /// 32-byte BLAKE2b of the whole file. Store it and recompute later to detect
  /// ANY change (reference-based tamper detection).
  Uint8List contentDigest(String path) => _l.stegoContentDigest(path);

  /// Heuristic hidden-data probe. See [StegoHiddenDataReport.note] for the
  /// limits - this is an indicator, not proof.
  StegoHiddenDataReport detectHidden(String path) => _l.stegoDetectHidden(path);
}
