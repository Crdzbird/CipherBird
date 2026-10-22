part of '../../cipher_bird.dart';

/// FIPS profile ECDSA on CipherBird (SHA-256, DER signatures).
extension CipherBirdFipsP256Sign on CipherBird {
  /// Sign [message].
  Uint8List fipsP256Sign(Uint8List privateKey, Uint8List message) {
    final privateKeyPtr = _toNative(privateKey);
    final messagePtr = _toNative(message);
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
        >('cryptolib_fips_p256_sign')(
          privateKeyPtr,
          privateKey.length,
          messagePtr,
          message.length,
        ),
      );
    } finally {
      if (privateKeyPtr != nullptr) calloc.free(privateKeyPtr);
      if (messagePtr != nullptr) calloc.free(messagePtr);
    }
  }

  /// Verify a signature.
  bool fipsP256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) {
    final publicKeyPtr = _toNative(publicKey);
    final messagePtr = _toNative(message);
    final signaturePtr = _toNative(signature);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_fips_p256_verify')(
            publicKeyPtr,
            publicKey.length,
            messagePtr,
            message.length,
            signaturePtr,
            signature.length,
          ) ==
          1;
    } finally {
      if (publicKeyPtr != nullptr) calloc.free(publicKeyPtr);
      if (messagePtr != nullptr) calloc.free(messagePtr);
      if (signaturePtr != nullptr) calloc.free(signaturePtr);
    }
  }
}
