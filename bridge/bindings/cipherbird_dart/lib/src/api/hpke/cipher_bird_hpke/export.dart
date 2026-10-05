part of '../../../cipher_bird.dart';

extension CipherBirdHpkeExport on CipherBird {
  Uint8List _hpkeExport(
    Pointer<Void> h,
    Uint8List exporterContext,
    int length,
  ) {
    final pc = exporterContext.isNotEmpty
        ? _toNative(exporterContext)
        : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_hpke_export')(h, pc, exporterContext.length, length),
      );
    } finally {
      if (pc != nullptr) calloc.free(pc);
    }
  }
}
