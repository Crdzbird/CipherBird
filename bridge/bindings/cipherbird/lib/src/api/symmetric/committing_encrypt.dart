part of '../../cipher_bird.dart';

/// Symmetric operations.
extension CipherBirdSymmetricCommittingEncrypt on CipherBird {
  /// Committing AEAD encrypt. Unlike a plain AEAD, the ciphertext binds the
  /// exact key, so it cannot be opened under a second key (no invisible
  /// salamander / partitioning-oracle attack). [key] is 32 bytes.
  Uint8List committingEncrypt(
    Uint8List plaintext,
    Uint8List key, [
    Uint8List? aad,
  ]) {
    final pp = _toNative(plaintext), pk = _toNative(key);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
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
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_committing_encrypt')(
          pp,
          plaintext.length,
          pk,
          key.length,
          pa,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
    }
  }
}
