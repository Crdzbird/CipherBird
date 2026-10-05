part of '../../../cipher_bird.dart';

/// Sealed-messaging methods on CipherBird (tier 0=Flagship, 1=Fortress).
extension CipherBirdSealedSealerFinish on CipherBird {
  (Uint8List, Uint8List) _sealedSealerFinalize(
    Pointer<Void> h,
    Uint8List? last,
  ) {
    final pl = (last != null && last.isNotEmpty) ? _toNative(last) : nullptr;
    final outTrailer = calloc<CipherBirdBuffer>();
    try {
      final ct = _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<CipherBirdBuffer>,
          ),
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<CipherBirdBuffer>,
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
