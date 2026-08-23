part of '../cryptolib.dart';

/// Stego operations.
extension CryptoLibStego on CryptoLib {
  // ── Steganography ─────────────────────────────────────────────────────────

  /// Embed raw bytes into a media file.
  void stegoEmbed(String coverPath, Uint8List payload, String outputPath) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(payload);
    final co = outputPath.toNativeUtf8();
    try {
      final r = _stegoEmbed(cc, pp, payload.length, co);
      _checkResult(r);
    } finally {
      calloc.free(cc);
      if (pp != nullptr) calloc.free(pp);
      calloc.free(co);
    }
  }

  /// Extract raw bytes from a stego media file.
  Uint8List stegoExtract(String stegoPath) {
    final cp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(_stegoExtract(cp));
    } finally {
      calloc.free(cp);
    }
  }

  /// Get the steganographic capacity of a cover file (in bytes).
  int stegoCapacity(String coverPath) {
    final cp = coverPath.toNativeUtf8();
    try {
      return _stegoCapacity(cp);
    } finally {
      calloc.free(cp);
    }
  }
}

/// Structural inspection of a media file — is it a valid carrier, and does its
/// real content match its extension?
class StegoFileInspection {
  const StegoFileInspection({
    required this.parses,
    required this.format,
    required this.extensionMatches,
    required this.width,
    required this.height,
    required this.fileSize,
    required this.detail,
  });

  /// The file is recognised and structurally plausible as a carrier.
  final bool parses;

  /// Format detected from the file's content.
  final MediaFormat format;

  /// Content format agrees with the filename extension. A `false` here on an
  /// otherwise valid file means the file was renamed — worth noticing.
  final bool extensionMatches;

  /// Pixel width (images only; 0 otherwise).
  final int width;

  /// Pixel height (images only; 0 otherwise).
  final int height;

  /// Size on disk, in bytes.
  final int fileSize;

  /// Human-readable summary of what was found.
  final String detail;
}

/// Result of a heuristic probe for hidden data.
///
/// Read this as a signal, never a verdict: [cryptolibPayload] is definitive
/// when true, but the statistical fields cannot prove that nothing is hidden.
class StegoHiddenDataReport {
  const StegoHiddenDataReport({
    required this.cryptolibPayload,
    required this.lsbChiSquare,
    required this.lsbEmbeddingLikelihood,
    required this.samplesAnalysed,
    required this.note,
  });

  /// An unkeyed CryptoLib payload was actually recovered — definitive.
  final bool cryptolibPayload;

  /// Raw chi-square statistic over least-significant bits.
  final double lsbChiSquare;

  /// Heuristic 0..1 likelihood of LSB embedding. High values warrant a look;
  /// low values prove nothing.
  final double lsbEmbeddingLikelihood;

  /// How many samples the analysis covered.
  final int samplesAnalysed;

  /// Caveat text describing the limits of this particular result.
  final String note;
}

/// Keyed, encrypted and diagnostic steganography.
extension CryptoLibStegoAdvanced on CryptoLib {
  // ── Keyed embedding — carrier placement depends on a key ──────────────────

  /// Embed [payload] into [coverPath] → [outputPath], permuting placement under
  /// [key]. Without the key an extractor cannot locate the bits.
  ///
  /// This hides *where* the data is; it does not encrypt it. Use
  /// [stegoEmbedEncrypted] when the payload itself must stay confidential.
  void stegoEmbedKeyed(String coverPath, Uint8List payload, String outputPath, Uint8List key) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(payload);
    final co = outputPath.toNativeUtf8();
    final kk = _toNative(key);
    try {
      _checkResult(_lib.lookupFunction<
          CryptoResult Function(Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoResult Function(Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Uint8>, int)>('cryptolib_stego_embed_keyed')(
        cc, pp, payload.length, co, kk, key.length));
    } finally {
      calloc.free(cc);
      if (pp != nullptr) calloc.free(pp);
      calloc.free(co);
      if (kk != nullptr) calloc.free(kk);
    }
  }

  /// Extract a [stegoEmbedKeyed] payload. Throws on the wrong key.
  Uint8List stegoExtractKeyed(String stegoPath, Uint8List key) {
    final sp = stegoPath.toNativeUtf8();
    final kk = _toNative(key);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, int)>('cryptolib_stego_extract_keyed')(
        sp, kk, key.length));
    } finally {
      calloc.free(sp);
      if (kk != nullptr) calloc.free(kk);
    }
  }

  // ── Encrypted embedding — AEAD first, then hide ───────────────────────────

  /// Authenticated-encrypt [plaintext] under [masterKey], then hide the
  /// ciphertext in [coverPath] → [outputPath].
  ///
  /// This is the one to reach for by default: confidentiality rests on the key,
  /// with the carrier adding concealment on top.
  void stegoEmbedEncrypted(String coverPath, Uint8List plaintext, String outputPath, Uint8List masterKey) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(plaintext);
    final co = outputPath.toNativeUtf8();
    final kk = _toNative(masterKey);
    try {
      _checkResult(_lib.lookupFunction<
          CryptoResult Function(Pointer<Utf8>, Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoResult Function(Pointer<Utf8>, Pointer<Uint8>, int, Pointer<Utf8>, Pointer<Uint8>, int)>('cryptolib_stego_embed_encrypted')(
        cc, pp, plaintext.length, co, kk, masterKey.length));
    } finally {
      calloc.free(cc);
      if (pp != nullptr) calloc.free(pp);
      calloc.free(co);
      if (kk != nullptr) calloc.free(kk);
    }
  }

  /// Extract and decrypt a [stegoEmbedEncrypted] payload. Fails closed on a
  /// wrong key or a tampered carrier.
  Uint8List stegoExtractDecrypt(String stegoPath, Uint8List masterKey) {
    final sp = stegoPath.toNativeUtf8();
    final kk = _toNative(masterKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, int)>('cryptolib_stego_extract_decrypt')(
        sp, kk, masterKey.length));
    } finally {
      calloc.free(sp);
      if (kk != nullptr) calloc.free(kk);
    }
  }

  // ── Diagnostics ───────────────────────────────────────────────────────────

  /// Inspect a media file's structural validity and true format.
  StegoFileInspection stegoInspect(String path) {
    final p = path.toNativeUtf8();
    try {
      final r = _lib.lookupFunction<
          CryptoFileInspection Function(Pointer<Utf8>),
          CryptoFileInspection Function(Pointer<Utf8>)>('cryptolib_stego_inspect')(p);
      if (r.error != nullptr) {
        final msg = r.error.toDartString();
        _strFree(r.error);
        if (r.detail != nullptr) _strFree(r.detail);
        throw Exception(msg);
      }
      final detail = r.detail == nullptr ? '' : r.detail.toDartString();
      if (r.detail != nullptr) _strFree(r.detail);
      return StegoFileInspection(
        parses: r.parses == 1,
        format: MediaFormat.fromValue(r.format),
        extensionMatches: r.extMatches == 1,
        width: r.width,
        height: r.height,
        fileSize: r.fileSize,
        detail: detail,
      );
    } finally {
      calloc.free(p);
    }
  }

  /// Probe [path] for hidden data.
  ///
  /// A positive [StegoHiddenDataReport.cryptolibPayload] is conclusive; the
  /// statistical fields are heuristics that can suggest embedding but can never
  /// establish its absence.
  StegoHiddenDataReport stegoDetectHidden(String path) {
    final p = path.toNativeUtf8();
    try {
      final r = _lib.lookupFunction<
          CryptoHiddenDataReport Function(Pointer<Utf8>),
          CryptoHiddenDataReport Function(Pointer<Utf8>)>('cryptolib_stego_detect_hidden')(p);
      if (r.error != nullptr) {
        final msg = r.error.toDartString();
        _strFree(r.error);
        if (r.note != nullptr) _strFree(r.note);
        throw Exception(msg);
      }
      final note = r.note == nullptr ? '' : r.note.toDartString();
      if (r.note != nullptr) _strFree(r.note);
      return StegoHiddenDataReport(
        cryptolibPayload: r.cryptolibPayload == 1,
        lsbChiSquare: r.lsbChiSquare,
        lsbEmbeddingLikelihood: r.lsbEmbeddingLikelihood,
        samplesAnalysed: r.samplesAnalysed,
        note: note,
      );
    } finally {
      calloc.free(p);
    }
  }

  /// Digest of a carrier's *decoded content* rather than its file bytes.
  ///
  /// Stable across re-encodings that preserve the samples/pixels, so it
  /// identifies the underlying media even when the container changes.
  Uint8List stegoContentDigest(String path) {
    final p = path.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Utf8>)>('cryptolib_stego_content_digest')(p));
    } finally {
      calloc.free(p);
    }
  }
}
