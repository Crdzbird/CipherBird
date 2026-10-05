part of '../../cipher_bird.dart';

/// Composed seal/open operations on CipherBird.
extension CipherBirdComposedHpkeStegoSeal on CipherBird {
  /// Seal [plaintext] to the recipient's HPKE public key [recipientPublic] and
  /// hide it in [coverPath] -> [outputPath].
  ///
  /// Returns the public KEM encapsulation (`enc`) - transmit it alongside the
  /// carrier, since the recipient needs it to open. Get keys from
  /// `hpkeKeygen()` / `hpkeDeriveKeyPair()`.
  Uint8List hpkeStegoSeal({
    required Uint8List recipientPublic,
    required Uint8List plaintext,
    required String coverPath,
    required String outputPath,
    Uint8List? aad,
    Uint8List? info,
  }) {
    final pk = _toNative(recipientPublic);
    final pt = _toNative(plaintext);
    final a = (aad == null || aad.isEmpty) ? nullptr : _toNative(aad);
    final i = (info == null || info.isEmpty) ? nullptr : _toNative(info);
    final cv = coverPath.toNativeUtf8();
    final out = outputPath.toNativeUtf8();
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Utf8>,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Utf8>,
          )
        >('cryptolib_hpke_stego_seal')(
          pk,
          recipientPublic.length,
          pt,
          plaintext.length,
          a,
          aad?.length ?? 0,
          i,
          info?.length ?? 0,
          cv,
          out,
        ),
      );
    } finally {
      if (pk != nullptr) {
        calloc.free(pk);
      }
      if (pt != nullptr) {
        calloc.free(pt);
      }
      if (a != nullptr) {
        calloc.free(a);
      }
      if (i != nullptr) {
        calloc.free(i);
      }
      calloc.free(cv);
      calloc.free(out);
    }
  }
}
