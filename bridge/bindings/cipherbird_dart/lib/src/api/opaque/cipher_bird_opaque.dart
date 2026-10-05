part of '../../cipher_bird.dart';

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CipherBird.
extension CipherBirdOpaque on CipherBird {
  /// Client registration step 1: blind the password -> {blind, request}.
  OprfBlindResult opaqueRegistrationRequest(Uint8List password) {
    final p = _toNative(password);
    try {
      final c = _lib
          .lookupFunction<
            CipherBirdOprfBlind Function(Pointer<Uint8>, Size),
            CipherBirdOprfBlind Function(Pointer<Uint8>, int)
          >('cryptolib_opaque_registration_request')(p, password.length);
      return _oprfBlindOut(c);
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Server registration step: -> 64-byte registration response.
  Uint8List opaqueRegistrationResponse(
    Uint8List request,
    Uint8List serverPublicKey,
    Uint8List credentialIdentifier,
    Uint8List oprfSeed,
  ) {
    final a = _toNative(request),
        b = _toNative(serverPublicKey),
        c = _toNative(credentialIdentifier),
        d = _toNative(oprfSeed);
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
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_opaque_registration_response')(
          a,
          request.length,
          b,
          serverPublicKey.length,
          c,
          credentialIdentifier.length,
          d,
          oprfSeed.length,
        ),
      );
    } finally {
      for (final x in [a, b, c, d]) {
        if (x != nullptr) calloc.free(x);
      }
    }
  }
}
