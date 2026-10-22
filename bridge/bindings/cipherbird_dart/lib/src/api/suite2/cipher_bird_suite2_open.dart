part of '../../cipher_bird.dart';

/// Suite v2 opening on CipherBird.
extension CipherBirdSuite2Open on CipherBird {
  /// Open an envelope; fails unless the signature over this recipient, ciphertext and [aad] verifies against [signerSigPublic].
  Uint8List suite2Open(
    Uint8List envelope,
    Uint8List recipientKemSecret,
    Uint8List recipientKemPublic,
    Uint8List signerSigPublic, {
    Uint8List? aad,
  }) {
    final envelopePtr = _toNative(envelope);
    final recipientKemSecretPtr = _toNative(recipientKemSecret);
    final recipientKemPublicPtr = _toNative(recipientKemPublic);
    final signerSigPublicPtr = _toNative(signerSigPublic);
    final aadPtr = aad == null ? nullptr : _toNative(aad);
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
          )
        >('cryptolib_suite2_open')(
          envelopePtr,
          envelope.length,
          recipientKemSecretPtr,
          recipientKemSecret.length,
          recipientKemPublicPtr,
          recipientKemPublic.length,
          signerSigPublicPtr,
          signerSigPublic.length,
          aadPtr,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (envelopePtr != nullptr) calloc.free(envelopePtr);
      if (recipientKemSecretPtr != nullptr) calloc.free(recipientKemSecretPtr);
      if (recipientKemPublicPtr != nullptr) calloc.free(recipientKemPublicPtr);
      if (signerSigPublicPtr != nullptr) calloc.free(signerSigPublicPtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
    }
  }
}
