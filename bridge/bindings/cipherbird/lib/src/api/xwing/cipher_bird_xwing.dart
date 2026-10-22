part of '../../cipher_bird.dart';

/// X-Wing (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing-kem) on CipherBird.
extension CipherBirdXWing on CipherBird {
  /// Fresh X-Wing key pair: public key 1216 bytes, secret key the 32-byte seed.
  KeyPairResult xwingKeygen() {
    return _extractKeyPair(
      _lib.lookupFunction<
        CipherBirdKeyPair Function(),
        CipherBirdKeyPair Function()
      >('cryptolib_xwing_keygen')(),
    );
  }

  /// The X-Wing key pair a 32-byte seed expands to.
  KeyPairResult xwingKeypairFromSeed(Uint8List seed) {
    final seedPtr = _toNative(seed);
    try {
      return _extractKeyPair(
        _lib.lookupFunction<
          CipherBirdKeyPair Function(Pointer<Uint8>, Size),
          CipherBirdKeyPair Function(Pointer<Uint8>, int)
        >('cryptolib_xwing_keypair_from_seed')(seedPtr, seed.length),
      );
    } finally {
      if (seedPtr != nullptr) calloc.free(seedPtr);
    }
  }

  /// Recover the shared secret from a ciphertext with the 32-byte seed.
  Uint8List xwingDecapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final ciphertextPtr = _toNative(ciphertext);
    final secretKeyPtr = _toNative(secretKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
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
          )
        >('cryptolib_xwing_decapsulate')(
          ciphertextPtr,
          ciphertext.length,
          secretKeyPtr,
          secretKey.length,
        ),
      );
    } finally {
      if (ciphertextPtr != nullptr) calloc.free(ciphertextPtr);
      if (secretKeyPtr != nullptr) calloc.free(secretKeyPtr);
    }
  }
}
