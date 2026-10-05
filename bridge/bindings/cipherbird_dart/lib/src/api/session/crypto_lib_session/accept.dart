part of '../../../cipher_bird.dart';

/// Session (ratchet) methods on CipherBird.
extension CipherBirdSessionAccept on CipherBird {
  /// Responder: accept a handshake with your prekey (public + secret).
  Session acceptSession(
    Uint8List handshake,
    Uint8List prekeyPublic,
    Uint8List prekeySecret,
  ) {
    final ph = _toNative(handshake),
        pub = _toNative(prekeyPublic),
        sec = _toNative(prekeySecret);
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
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_session_accept')(
            ph,
            handshake.length,
            pub,
            prekeyPublic.length,
            sec,
            prekeySecret.length,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cipherbird: session accept failed');
      }
      return Session(this, h);
    } finally {
      if (ph != nullptr) {
        calloc.free(ph);
      }
      if (pub != nullptr) {
        calloc.free(pub);
      }
      if (sec != nullptr) {
        calloc.free(sec);
      }
      calloc.free(errPtr);
    }
  }

  Uint8List _sessionHandshake(Pointer<Void> h) => _checkBufResult(
    _lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>),
      CryptoBufferResult Function(Pointer<Void>)
    >('cryptolib_session_handshake')(h),
  );
}
