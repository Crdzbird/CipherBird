part of '../../cipher_bird.dart';

/// FIPS profile P-256 keys and ECDH on CipherBird: 65-byte public keys, 32-byte private scalars.
extension CipherBirdFipsP256 on CipherBird {
  /// Key pair from the module.
  KeyPairResult fipsP256Keygen() {
    return _extractKeyPair(
      _lib.lookupFunction<
        CipherBirdKeyPair Function(),
        CipherBirdKeyPair Function()
      >('cryptolib_fips_p256_keygen')(),
    );
  }

  /// ECDH shared secret (32 bytes).
  Uint8List fipsP256Ecdh(Uint8List privateKey, Uint8List peerPublic) {
    final privateKeyPtr = _toNative(privateKey);
    final peerPublicPtr = _toNative(peerPublic);
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
        >('cryptolib_fips_p256_ecdh')(
          privateKeyPtr,
          privateKey.length,
          peerPublicPtr,
          peerPublic.length,
        ),
      );
    } finally {
      if (privateKeyPtr != nullptr) calloc.free(privateKeyPtr);
      if (peerPublicPtr != nullptr) calloc.free(peerPublicPtr);
    }
  }

  /// The public point of a private scalar, computed by libcrypto outside the module boundary.
  Uint8List fipsP256PublicKey(Uint8List privateKey) {
    final privateKeyPtr = _toNative(privateKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Uint8>, int)
        >('cryptolib_fips_p256_public_key')(privateKeyPtr, privateKey.length),
      );
    } finally {
      if (privateKeyPtr != nullptr) calloc.free(privateKeyPtr);
    }
  }
}
