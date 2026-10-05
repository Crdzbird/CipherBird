part of '../../cipher_bird.dart';

/// Session (ratchet) methods on CipherBird.
extension CipherBirdSession on CipherBird {
  /// Responder: generate a prekey (hybrid-KEM keypair). Publish publicKey.
  KeyPairResult generateSessionPrekey() => _extractKeyPair(
    _lib.lookupFunction<
      CipherBirdKeyPair Function(),
      CipherBirdKeyPair Function()
    >(
      'cryptolib_session_generate_prekey',
    )(),
  );

  /// Initiator: start a session to the responder's prekey public key.
  Session initiateSession(Uint8List responderPrekeyPublic) {
    final pp = _toNative(responderPrekeyPublic);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib
          .lookupFunction<
            Pointer<Void> Function(
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)
          >(
            'cryptolib_session_initiate',
          )(pp, responderPrekeyPublic.length, errPtr);
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cipherbird: session initiate failed');
      }
      return Session(this, h);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(errPtr);
    }
  }
}
