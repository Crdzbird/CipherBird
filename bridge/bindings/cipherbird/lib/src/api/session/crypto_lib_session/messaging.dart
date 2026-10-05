part of '../../../cipher_bird.dart';

/// Session (ratchet) methods on CipherBird.
extension CipherBirdSessionMessaging on CipherBird {
  Uint8List _sessionMsg(
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
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
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

  void _sessionFree(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_session_free')(h);
}
