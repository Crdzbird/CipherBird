part of '../../cipher_bird.dart';

/// FIPS profile AES-256-GCM on CipherBird; the IV is built inside the module.
extension CipherBirdFipsAesGcm on CipherBird {
  /// Encrypt: wire = iv(12) | ciphertext | tag(16).
  Uint8List fipsAesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    final keyPtr = _toNative(key);
    final plaintextPtr = _toNative(plaintext);
    final aadPtr = aad == null ? nullptr : _toNative(aad);
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
        >('cryptolib_fips_aes_gcm_encrypt')(
          keyPtr,
          key.length,
          plaintextPtr,
          plaintext.length,
          aadPtr,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (keyPtr != nullptr) calloc.free(keyPtr);
      if (plaintextPtr != nullptr) calloc.free(plaintextPtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
    }
  }

  /// Decrypt a wire blob; any failure is "authentication failed".
  Uint8List fipsAesGcmDecrypt(Uint8List key, Uint8List wire, {Uint8List? aad}) {
    final keyPtr = _toNative(key);
    final wirePtr = _toNative(wire);
    final aadPtr = aad == null ? nullptr : _toNative(aad);
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
        >('cryptolib_fips_aes_gcm_decrypt')(
          keyPtr,
          key.length,
          wirePtr,
          wire.length,
          aadPtr,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (keyPtr != nullptr) calloc.free(keyPtr);
      if (wirePtr != nullptr) calloc.free(wirePtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
    }
  }
}
