part of '../../cryptolib.dart';

extension CryptoLibSlhDsaVerify on CryptoLib {
  bool slhDsaVerify(
    Uint8List msg,
    Uint8List sig,
    Uint8List publicKey,
    SlhDsaLevel level,
    SlhDsaHash hash,
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
              int,
            )
          >('cryptolib_slh_dsa_verify')(
            mp,
            msg.length,
            sgp,
            sig.length,
            pp,
            publicKey.length,
            level.value,
            hash.value,
          ) ==
          1;
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }
}
