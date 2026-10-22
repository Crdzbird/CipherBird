part of '../../../cipher_bird.dart';

/// Session v2 acceptance on CipherBird.
extension CipherBirdSession2Accept on CipherBird {
  /// Responder: accept [handshake] only from [expectedInitiatorSigPublic], with the prekey bundle and its seed and the responder identity.
  Session2 acceptSession2(
    Uint8List handshake,
    Uint8List bundle,
    Uint8List prekeySecret,
    Uint8List responderSigPublic,
    Uint8List responderSigSecret,
    Uint8List expectedInitiatorSigPublic,
  ) {
    final handshakePtr = _toNative(handshake);
    final bundlePtr = _toNative(bundle);
    final prekeySecretPtr = _toNative(prekeySecret);
    final responderSigPublicPtr = _toNative(responderSigPublic);
    final responderSigSecretPtr = _toNative(responderSigSecret);
    final expectedInitiatorSigPublicPtr = _toNative(expectedInitiatorSigPublic);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_session2_accept')(
            handshakePtr,
            handshake.length,
            bundlePtr,
            bundle.length,
            prekeySecretPtr,
            prekeySecret.length,
            responderSigPublicPtr,
            responderSigPublic.length,
            responderSigSecretPtr,
            responderSigSecret.length,
            expectedInitiatorSigPublicPtr,
            expectedInitiatorSigPublic.length,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cipherbird: session2 accept failed');
      }
      return Session2(this, h);
    } finally {
      if (handshakePtr != nullptr) {
        calloc.free(handshakePtr);
      }
      if (bundlePtr != nullptr) {
        calloc.free(bundlePtr);
      }
      if (prekeySecretPtr != nullptr) {
        calloc.free(prekeySecretPtr);
      }
      if (responderSigPublicPtr != nullptr) {
        calloc.free(responderSigPublicPtr);
      }
      if (responderSigSecretPtr != nullptr) {
        calloc.free(responderSigSecretPtr);
      }
      if (expectedInitiatorSigPublicPtr != nullptr) {
        calloc.free(expectedInitiatorSigPublicPtr);
      }
      calloc.free(errPtr);
    }
  }
}
