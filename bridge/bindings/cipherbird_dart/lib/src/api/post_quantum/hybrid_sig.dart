part of '../../cipher_bird.dart';

/// PostQuantum operations.
extension CipherBirdHybridSig on CipherBird {
  bool hybridSigVerify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_hybrid_sig_verify')(
            mp,
            msg.length,
            sgp,
            sig.length,
            pp,
            publicKey.length,
          ) ==
          1;
    } finally {
      if (mp != nullptr) {
        calloc.free(mp);
      }
      if (sgp != nullptr) {
        calloc.free(sgp);
      }
      if (pp != nullptr) {
        calloc.free(pp);
      }
    }
  }

  KeyPairResult hybridSigKeygen() => _extractKeyPair(
    _lib.lookupFunction<
      CipherBirdKeyPair Function(),
      CipherBirdKeyPair Function()
    >(
      'cryptolib_hybrid_sig_keygen',
    )(),
  );

  Uint8List hybridSigSign(Uint8List msg, Uint8List secretKey) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
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
        >('cryptolib_hybrid_sig_sign')(mp, msg.length, sp, secretKey.length),
      );
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sp != nullptr) calloc.free(sp);
    }
  }
}
