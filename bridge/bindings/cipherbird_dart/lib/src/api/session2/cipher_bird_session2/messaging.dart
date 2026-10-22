part of '../../../cipher_bird.dart';

/// Session v2 messaging on CipherBird.
extension CipherBirdSession2Messaging on CipherBird {
  Uint8List _session2Msg(
    String symbol,
    Pointer<Void> h,
    Uint8List data,
    Uint8List? aad,
  ) {
    final pd = _toNative(data);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >(symbol)(h, pd, data.length, pa, aad?.length ?? 0),
      );
    } finally {
      if (pd != nullptr) calloc.free(pd);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  void _session2Free(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_session2_free')(h);

  Uint8List _session2Handshake(Pointer<Void> h) {
    return _checkBufResult(
      _lib.lookupFunction<
        CipherBirdBufferResult Function(Pointer<Void>),
        CipherBirdBufferResult Function(Pointer<Void>)
      >('cryptolib_session2_handshake')(h),
    );
  }
}
