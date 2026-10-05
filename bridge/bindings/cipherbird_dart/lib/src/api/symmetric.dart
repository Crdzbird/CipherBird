part of '../cipher_bird.dart';

/// Symmetric operations.
extension CipherBirdSymmetric on CipherBird {
  /// Generate a 32-byte random symmetric key.
  Uint8List symKeygen() => _checkBufResult(_symmetric.symKeygen());

  /// XChaCha20-Poly1305 encrypt.
  Uint8List xchacha20Encrypt(
    Uint8List plaintext,
    Uint8List key, [
    Uint8List? aad,
  ]) {
    final pp = _toNative(plaintext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(
        _symmetric.xchacha20Enc(pp, plaintext.length, pk, key.length, pa, al),
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

  /// XChaCha20-Poly1305 decrypt.
  Uint8List xchacha20Decrypt(
    Uint8List ciphertext,
    Uint8List key, [
    Uint8List? aad,
  ]) {
    final pc = _toNative(ciphertext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(
        _symmetric.xchacha20Dec(pc, ciphertext.length, pk, key.length, pa, al),
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
