part of '../../cryptolib.dart';

/// Symmetric operations.
extension CryptoLibAes256Gcm on CryptoLib {
  /// AES-256-GCM encrypt.
  Uint8List aes256gcmEncrypt(
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
        _symmetric.aes256gcmEnc(pp, plaintext.length, pk, key.length, pa, al),
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

  /// AES-256-GCM decrypt.
  Uint8List aes256gcmDecrypt(
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
        _symmetric.aes256gcmDec(pc, ciphertext.length, pk, key.length, pa, al),
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

  /// Check if AES-256-GCM is available on this CPU.
  bool aes256gcmAvailable() => _symmetric.aes256gcmAvailable() != 0;
}
