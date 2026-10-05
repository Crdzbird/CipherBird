part of '../../../cipher_bird.dart';

/// Sealed-messaging methods on CipherBird (tier 0=Flagship, 1=Fortress).
extension CipherBirdSealedSealer on CipherBird {
  SealedStreamSealer sealedSealerBegin(
    SealedTier tier,
    Uint8List recipientPublic,
    Uint8List senderSecret, {
    Uint8List? purpose,
  }) {
    final pr = _toNative(recipientPublic), ps = _toNative(senderSecret);
    final pu = (purpose != null && purpose.isNotEmpty)
        ? _toNative(purpose)
        : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
              Int32,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_sealed_sealer_begin')(
            tier.value,
            pr,
            recipientPublic.length,
            ps,
            senderSecret.length,
            pu,
            purpose?.length ?? 0,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cipherbird: stream sealer begin failed');
      }
      return SealedStreamSealer(this, h);
    } finally {
      if (pr != nullptr) {
        calloc.free(pr);
      }
      if (ps != nullptr) {
        calloc.free(ps);
      }
      if (pu != nullptr) {
        calloc.free(pu);
      }
      calloc.free(errPtr);
    }
  }

  Uint8List _sealedSealerPreamble(Pointer<Void> h) => _checkBufResult(
    _lib.lookupFunction<
      CipherBirdBufferResult Function(Pointer<Void>),
      CipherBirdBufferResult Function(Pointer<Void>)
    >('cryptolib_sealed_sealer_preamble')(h),
  );

  Uint8List _sealedSealerPush(Pointer<Void> h, Uint8List chunk) {
    final pc = _toNative(chunk);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_sealed_sealer_push')(h, pc, chunk.length),
      );
    } finally {
      if (pc != nullptr) calloc.free(pc);
    }
  }
}
