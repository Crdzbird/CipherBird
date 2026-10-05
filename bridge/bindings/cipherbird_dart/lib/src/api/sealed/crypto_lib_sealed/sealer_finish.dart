part of '../../../cryptolib.dart';

/// Sealed-messaging methods on CryptoLib (tier 0=Flagship, 1=Fortress).
extension CryptoLibSealedSealerFinish on CryptoLib {
  (Uint8List, Uint8List) _sealedSealerFinalize(
    Pointer<Void> h,
    Uint8List? last,
  ) {
    final pl = (last != null && last.isNotEmpty) ? _toNative(last) : nullptr;
    final outTrailer = calloc<CryptoBuffer>();
    try {
      final ct = _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<CryptoBuffer>,
          ),
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<CryptoBuffer>,
          )
        >('cryptolib_sealed_sealer_finalize')(
          h,
          pl,
          last?.length ?? 0,
          outTrailer,
        ),
      );
      return (ct, _copyBuf(outTrailer.ref));
    } finally {
      if (pl != nullptr) calloc.free(pl);
      calloc.free(outTrailer);
    }
  }

  void _sealedSealerFree(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_sealed_sealer_free')(h);
}
