part of '../../cipher_bird.dart';

/// Keyed, encrypted and diagnostic steganography.
extension CipherBirdStegoAdvanced on CipherBird {
  /// Embed [payload] into [coverPath] -> [outputPath], permuting placement under
  /// [key]. Without the key an extractor cannot locate the bits.
  ///
  /// This hides *where* the data is; it does not encrypt it. Use
  /// [stegoEmbedEncrypted] when the payload itself must stay confidential.
  void stegoEmbedKeyed(
    String coverPath,
    Uint8List payload,
    String outputPath,
    Uint8List key,
  ) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(payload);
    final co = outputPath.toNativeUtf8();
    final kk = _toNative(key);
    try {
      _checkResult(
        _lib.lookupFunction<
          CipherBirdResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_stego_embed_keyed')(
          cc,
          pp,
          payload.length,
          co,
          kk,
          key.length,
        ),
      );
    } finally {
      calloc.free(cc);
      if (pp != nullptr) {
        calloc.free(pp);
      }
      calloc.free(co);
      if (kk != nullptr) {
        calloc.free(kk);
      }
    }
  }

  /// Extract a [stegoEmbedKeyed] payload. Throws on the wrong key.
  Uint8List stegoExtractKeyed(String stegoPath, Uint8List key) {
    final sp = stegoPath.toNativeUtf8();
    final kk = _toNative(key);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, int)
        >('cryptolib_stego_extract_keyed')(sp, kk, key.length),
      );
    } finally {
      calloc.free(sp);
      if (kk != nullptr) {
        calloc.free(kk);
      }
    }
  }
}
