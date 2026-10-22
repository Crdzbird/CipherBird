part of '../../cipher_bird.dart';

extension CipherBirdFipsEnvelopeOps on CipherBird {
  void _fipsEnvelopeAddPassphrase(
    Pointer<Void> h,
    Uint8List passphrase,
    int iterations,
  ) {
    final passphrasePtr = _toNative(passphrase);
    try {
      _checkResult(
        _lib.lookupFunction<
          CipherBirdResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Uint32,
          ),
          CipherBirdResult Function(Pointer<Void>, Pointer<Uint8>, int, int)
        >('cryptolib_fips_envelope_add_passphrase_slot')(
          h,
          passphrasePtr,
          passphrase.length,
          iterations,
        ),
      );
    } finally {
      if (passphrasePtr != nullptr) calloc.free(passphrasePtr);
    }
  }

  void _fipsEnvelopeAddKey(Pointer<Void> h, Uint8List factor) {
    final factorPtr = _toNative(factor);
    try {
      _checkResult(
        _lib.lookupFunction<
          CipherBirdResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CipherBirdResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_fips_envelope_add_key_slot')(h, factorPtr, factor.length),
      );
    } finally {
      if (factorPtr != nullptr) calloc.free(factorPtr);
    }
  }

  Uint8List _fipsEnvelopeUnlockPassphrase(
    Pointer<Void> h,
    Uint8List passphrase,
  ) {
    final passphrasePtr = _toNative(passphrase);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_fips_envelope_unlock_with_passphrase')(
          h,
          passphrasePtr,
          passphrase.length,
        ),
      );
    } finally {
      if (passphrasePtr != nullptr) calloc.free(passphrasePtr);
    }
  }

  Uint8List _fipsEnvelopeUnlockKey(Pointer<Void> h, Uint8List factor) {
    final factorPtr = _toNative(factor);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_fips_envelope_unlock_with_key')(
          h,
          factorPtr,
          factor.length,
        ),
      );
    } finally {
      if (factorPtr != nullptr) calloc.free(factorPtr);
    }
  }
}
