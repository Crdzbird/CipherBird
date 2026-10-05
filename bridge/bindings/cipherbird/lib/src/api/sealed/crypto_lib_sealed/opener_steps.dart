part of '../../../cryptolib.dart';

/// Sealed-messaging methods on CryptoLib (tier 0=Flagship, 1=Fortress).
extension CryptoLibSealedOpenerSteps on CryptoLib {
  (Uint8List, bool) _sealedOpenerPull(Pointer<Void> h, Uint8List ct) {
    final pc = _toNative(ct);
    final outFinal = calloc<Int32>();
    try {
      final pt = _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Int32>,
          ),
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Int32>,
          )
        >('cryptolib_sealed_opener_pull')(h, pc, ct.length, outFinal),
      );
      return (pt, outFinal.value == 1);
    } finally {
      if (pc != nullptr) calloc.free(pc);
      calloc.free(outFinal);
    }
  }

  void _sealedOpenerFinalize(Pointer<Void> h, Uint8List trailer) {
    final pt = _toNative(trailer);
    try {
      _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_sealed_opener_finalize')(h, pt, trailer.length),
      );
    } finally {
      if (pt != nullptr) calloc.free(pt);
    }
  }

  void _sealedOpenerFree(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_sealed_opener_free')(h);
}
