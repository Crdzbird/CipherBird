part of '../../../cipher_bird.dart';

/// Keyed, encrypted and diagnostic steganography.
extension CipherBirdStegoInspection on CipherBird {
  /// Inspect a media file's structural validity and true format.
  StegoFileInspection stegoInspect(String path) {
    final p = path.toNativeUtf8();
    try {
      final r = _lib
          .lookupFunction<
            CipherBirdFileInspection Function(Pointer<Utf8>),
            CipherBirdFileInspection Function(Pointer<Utf8>)
          >('cryptolib_stego_inspect')(p);
      if (r.error != nullptr) {
        final msg = r.error.toDartString();
        _core.strFree(r.error);
        if (r.detail != nullptr) {
          _core.strFree(r.detail);
        }
        throw Exception(msg);
      }
      final detail = r.detail == nullptr ? '' : r.detail.toDartString();
      if (r.detail != nullptr) {
        _core.strFree(r.detail);
      }
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
  /// A positive [StegoHiddenDataReport.cipherbirdPayload] is conclusive; the
  /// statistical fields are heuristics that can suggest embedding but can never
  /// establish its absence.
  StegoHiddenDataReport stegoDetectHidden(String path) {
    final p = path.toNativeUtf8();
    try {
      final r = _lib
          .lookupFunction<
            CipherBirdHiddenDataReport Function(Pointer<Utf8>),
            CipherBirdHiddenDataReport Function(Pointer<Utf8>)
          >('cryptolib_stego_detect_hidden')(p);
      if (r.error != nullptr) {
        final msg = r.error.toDartString();
        _core.strFree(r.error);
        if (r.note != nullptr) {
          _core.strFree(r.note);
        }
        throw Exception(msg);
      }
      final note = r.note == nullptr ? '' : r.note.toDartString();
      if (r.note != nullptr) {
        _core.strFree(r.note);
      }
      return StegoHiddenDataReport(
        cipherbirdPayload: r.cipherbirdPayload == 1,
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
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Utf8>),
          CipherBirdBufferResult Function(Pointer<Utf8>)
        >('cryptolib_stego_content_digest')(p),
      );
    } finally {
      calloc.free(p);
    }
  }
}
