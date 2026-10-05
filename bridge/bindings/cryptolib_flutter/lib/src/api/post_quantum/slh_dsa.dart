part of '../../cryptolib.dart';

/// PostQuantum operations.
extension CryptoLibSlhDsa on CryptoLib {
  KeyPairResult slhDsaKeygen(SlhDsaLevel level, SlhDsaHash hash) =>
      _extractKeyPair(
        _lib.lookupFunction<
          CryptoKeyPair Function(Int32, Int32),
          CryptoKeyPair Function(int, int)
        >('cryptolib_slh_dsa_keygen')(level.value, hash.value),
      );

  Uint8List slhDsaSign(
    Uint8List msg,
    Uint8List secretKey,
    SlhDsaLevel level,
    SlhDsaHash hash,
  ) {
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
            Int32,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            int,
            int,
          )
        >('cryptolib_slh_dsa_sign')(
          mp,
          msg.length,
          sp,
          secretKey.length,
          level.value,
          hash.value,
        ),
      );
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sp != nullptr) calloc.free(sp);
    }
  }
}
