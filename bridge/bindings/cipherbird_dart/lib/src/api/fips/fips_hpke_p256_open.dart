part of '../../cipher_bird.dart';

/// FIPS profile HPKE (DHKEM(P-256), HKDF-SHA256, AES-256-GCM) opening on CipherBird.
extension CipherBirdFipsHpkeP256Open on CipherBird {
  /// Open a one-shot HPKE message with the recipient private and public keys.
  Uint8List fipsHpkeP256Open(
    Uint8List enc,
    Uint8List recipientSecret,
    Uint8List recipientPublic,
    Uint8List ciphertext, {
    Uint8List? info,
    Uint8List? aad,
  }) {
    final encPtr = _toNative(enc);
    final recipientSecretPtr = _toNative(recipientSecret);
    final recipientPublicPtr = _toNative(recipientPublic);
    final infoPtr = info == null ? nullptr : _toNative(info);
    final aadPtr = aad == null ? nullptr : _toNative(aad);
    final ciphertextPtr = _toNative(ciphertext);
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
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_fips_hpke_p256_open')(
          encPtr,
          enc.length,
          recipientSecretPtr,
          recipientSecret.length,
          recipientPublicPtr,
          recipientPublic.length,
          infoPtr,
          info?.length ?? 0,
          aadPtr,
          aad?.length ?? 0,
          ciphertextPtr,
          ciphertext.length,
        ),
      );
    } finally {
      if (encPtr != nullptr) calloc.free(encPtr);
      if (recipientSecretPtr != nullptr) calloc.free(recipientSecretPtr);
      if (recipientPublicPtr != nullptr) calloc.free(recipientPublicPtr);
      if (infoPtr != nullptr) calloc.free(infoPtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
      if (ciphertextPtr != nullptr) calloc.free(ciphertextPtr);
    }
  }
}
