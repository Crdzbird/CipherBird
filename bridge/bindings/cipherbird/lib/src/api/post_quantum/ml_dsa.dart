part of '../../cryptolib.dart';

/// PostQuantum operations.
extension CryptoLibMlDsa on CryptoLib {
  bool mlDsaVerify(
    Uint8List msg,
    Uint8List sig,
    Uint8List publicKey,
    MlDsaLevel level,
  ) {
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
              Int32,
            ),
            int Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              int,
            )
          >('cryptolib_ml_dsa_verify')(
            mp,
            msg.length,
            sgp,
            sig.length,
            pp,
            publicKey.length,
            level.value,
          ) ==
          1;
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }

  KeyPairResult mlDsaKeygen(MlDsaLevel level) => _extractKeyPair(
    _lib.lookupFunction<
      CryptoKeyPair Function(Int32),
      CryptoKeyPair Function(int)
    >('cryptolib_ml_dsa_keygen')(level.value),
  );

  Uint8List mlDsaSign(Uint8List msg, Uint8List secretKey, MlDsaLevel level) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Int32,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_ml_dsa_sign')(
          mp,
          msg.length,
          sp,
          secretKey.length,
          level.value,
        ),
      );
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sp != nullptr) calloc.free(sp);
    }
  }
}
