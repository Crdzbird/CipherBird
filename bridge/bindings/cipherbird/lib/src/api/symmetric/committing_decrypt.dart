part of '../../cipher_bird.dart';

/// Symmetric operations.
extension CipherBirdSymmetricCommittingDecrypt on CipherBird {
  /// Committing AEAD decrypt. Throws if the key/AAD don't match or the
  /// commitment check fails. [key] is 32 bytes.
  Uint8List committingDecrypt(
    Uint8List ciphertext,
    Uint8List key, [
    Uint8List? aad,
  ]) {
    final pc = _toNative(ciphertext), pk = _toNative(key);
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
        >('cryptolib_committing_decrypt')(
          pc,
          ciphertext.length,
          pk,
          key.length,
          pa,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pc != nullptr) {
        calloc.free(pc);
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
