part of '../../../cipher_bird.dart';

/// Session v2 initiation on CipherBird.
extension CipherBirdSession2Initiate on CipherBird {
  /// Initiator: verify [bundle] against [responderSigPublic], key to it and sign the handshake with the initiator identity.
  Session2 initiateSession2(
    Uint8List bundle,
    Uint8List responderSigPublic,
    Uint8List initiatorSigPublic,
    Uint8List initiatorSigSecret,
  ) {
    final bundlePtr = _toNative(bundle);
    final responderSigPublicPtr = _toNative(responderSigPublic);
    final initiatorSigPublicPtr = _toNative(initiatorSigPublic);
    final initiatorSigSecretPtr = _toNative(initiatorSigSecret);
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
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_session2_initiate')(
            bundlePtr,
            bundle.length,
            responderSigPublicPtr,
            responderSigPublic.length,
            initiatorSigPublicPtr,
            initiatorSigPublic.length,
            initiatorSigSecretPtr,
            initiatorSigSecret.length,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cipherbird: session2 initiate failed');
      }
      return Session2(this, h);
    } finally {
      if (bundlePtr != nullptr) {
        calloc.free(bundlePtr);
      }
      if (responderSigPublicPtr != nullptr) {
        calloc.free(responderSigPublicPtr);
      }
      if (initiatorSigPublicPtr != nullptr) {
        calloc.free(initiatorSigPublicPtr);
      }
      if (initiatorSigSecretPtr != nullptr) {
        calloc.free(initiatorSigSecretPtr);
      }
      calloc.free(errPtr);
    }
  }
}
