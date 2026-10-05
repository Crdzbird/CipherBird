part of '../../../cipher_bird.dart';

/// Keyed, encrypted and diagnostic steganography.
extension CipherBirdStegoEncrypted on CipherBird {
  /// Authenticated-encrypt [plaintext] under [masterKey], then hide the
  /// ciphertext in [coverPath] -> [outputPath].
  ///
  /// This is the one to reach for by default: confidentiality rests on the key,
  /// with the carrier adding concealment on top.
  void stegoEmbedEncrypted(
    String coverPath,
    Uint8List plaintext,
    String outputPath,
    Uint8List masterKey,
  ) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(plaintext);
    final co = outputPath.toNativeUtf8();
    final kk = _toNative(masterKey);
    try {
      _checkResult(
        _lib.lookupFunction<
          CryptoResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
          ),
          CryptoResult Function(
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_stego_embed_encrypted')(
          cc,
          pp,
          plaintext.length,
          co,
          kk,
          masterKey.length,
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

  /// Extract and decrypt a [stegoEmbedEncrypted] payload. Fails closed on a
  /// wrong key or a tampered carrier.
  Uint8List stegoExtractDecrypt(String stegoPath, Uint8List masterKey) {
    final sp = stegoPath.toNativeUtf8();
    final kk = _toNative(masterKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, int)
        >('cryptolib_stego_extract_decrypt')(sp, kk, masterKey.length),
      );
    } finally {
      calloc.free(sp);
      if (kk != nullptr) {
        calloc.free(kk);
      }
    }
  }
}
