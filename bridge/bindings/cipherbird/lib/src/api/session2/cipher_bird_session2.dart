part of '../../cipher_bird.dart';

/// Session v2 prekeys on CipherBird.
extension CipherBirdSession2 on CipherBird {
  /// Responder: publicKey is the signed prekey bundle to publish, secretKey the 32-byte X-Wing seed to keep.
  KeyPairResult generateSession2Prekey(Uint8List responderSigSecret) {
    final responderSigSecretPtr = _toNative(responderSigSecret);
    try {
      return _extractKeyPair(
        _lib.lookupFunction<
          CipherBirdKeyPair Function(Pointer<Uint8>, Size),
          CipherBirdKeyPair Function(Pointer<Uint8>, int)
        >('cryptolib_session2_generate_prekey')(
          responderSigSecretPtr,
          responderSigSecret.length,
        ),
      );
    } finally {
      if (responderSigSecretPtr != nullptr) calloc.free(responderSigSecretPtr);
    }
  }

  /// The X-Wing public key inside [bundle], after its signature verified against [responderSigPublic].
  Uint8List verifySession2Prekey(
    Uint8List bundle,
    Uint8List responderSigPublic,
  ) {
    final bundlePtr = _toNative(bundle);
    final responderSigPublicPtr = _toNative(responderSigPublic);
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
        >('cryptolib_session2_verify_prekey')(
          bundlePtr,
          bundle.length,
          responderSigPublicPtr,
          responderSigPublic.length,
        ),
      );
    } finally {
      if (bundlePtr != nullptr) calloc.free(bundlePtr);
      if (responderSigPublicPtr != nullptr) calloc.free(responderSigPublicPtr);
    }
  }

  /// The initiator identity a handshake claims, before verification. Look the expected identity up with it; never trust it.
  Uint8List claimedSession2Initiator(Uint8List handshake) {
    final handshakePtr = _toNative(handshake);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Uint8>, int)
        >('cryptolib_session2_claimed_initiator')(
          handshakePtr,
          handshake.length,
        ),
      );
    } finally {
      if (handshakePtr != nullptr) calloc.free(handshakePtr);
    }
  }
}
