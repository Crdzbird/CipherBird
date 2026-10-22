part of '../../cipher_bird.dart';

/// Suite v2 signed sealed envelopes on CipherBird: the signature binds recipient, KEM ciphertext and AAD.
extension CipherBirdSuite2 on CipherBird {
  /// Seal [plaintext] to [recipientKemPublic], signed by [signerSigSecret] (hybridSigKeygen).
  Uint8List suite2Seal(
    Uint8List plaintext,
    Uint8List recipientKemPublic,
    Uint8List signerSigSecret, {
    Uint8List? aad,
    Suite2Id suite = Suite2Id.xWingSig,
  }) {
    final plaintextPtr = _toNative(plaintext);
    final recipientKemPublicPtr = _toNative(recipientKemPublic);
    final signerSigSecretPtr = _toNative(signerSigSecret);
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
            Int32,
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
            int,
          )
        >('cryptolib_suite2_seal')(
          plaintextPtr,
          plaintext.length,
          recipientKemPublicPtr,
          recipientKemPublic.length,
          signerSigSecretPtr,
          signerSigSecret.length,
          aadPtr,
          aad?.length ?? 0,
          suite.value,
        ),
      );
    } finally {
      if (plaintextPtr != nullptr) calloc.free(plaintextPtr);
      if (recipientKemPublicPtr != nullptr) calloc.free(recipientKemPublicPtr);
      if (signerSigSecretPtr != nullptr) calloc.free(signerSigSecretPtr);
      if (aadPtr != nullptr) calloc.free(aadPtr);
    }
  }

  /// The suite id of a v2 envelope, or 0 when it is not one.
  int suite2SuiteOf(Uint8List envelope) {
    final envelopePtr = _toNative(envelope);
    try {
      return _lib.lookupFunction<
        Int32 Function(Pointer<Uint8>, Size),
        int Function(Pointer<Uint8>, int)
      >('cryptolib_suite2_suite_of')(envelopePtr, envelope.length);
    } finally {
      if (envelopePtr != nullptr) calloc.free(envelopePtr);
    }
  }
}
