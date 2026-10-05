part of '../cipher_bird.dart';

/// Bls operations.
extension CipherBirdBls on CipherBird {
  KeyPairResult blsKeygen() => _extractKeyPair(
    _lib.lookupFunction<
      CipherBirdKeyPair Function(),
      CipherBirdKeyPair Function()
    >(
      'cryptolib_bls_keygen',
    )(),
  );

  Uint8List blsSign(Uint8List msg, Uint8List secretKey) {
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
        >('cryptolib_bls_sign')(mp, msg.length, sp, secretKey.length),
      );
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sp != nullptr) calloc.free(sp);
    }
  }

  bool blsVerify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
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
          >('cryptolib_bls_verify')(
            mp,
            msg.length,
            sgp,
            sig.length,
            pp,
            publicKey.length,
          ) ==
          1;
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }

  /// Deterministic BLS keygen from input key material. [ikm] must be >= 32
  /// bytes (per IRTF draft-irtf-cfrg-bls-signature KeyGen). Same IKM -> same key.
  KeyPairResult blsKeygenFromIkm(Uint8List ikm) {
    if (ikm.length < 32) {
      throw ArgumentError(
        'BLS keygen IKM must be >= 32 bytes, got ${ikm.length}',
      );
    }
    final ip = _toNative(ikm);
    try {
      return _extractKeyPair(
        _lib.lookupFunction<
          CipherBirdKeyPair Function(Pointer<Uint8>, Size),
          CipherBirdKeyPair Function(Pointer<Uint8>, int)
        >('cryptolib_bls_keygen_from_ikm')(ip, ikm.length),
      );
    } finally {
      if (ip != nullptr) calloc.free(ip);
    }
  }
}
