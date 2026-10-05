part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsSign on CipherBird {
  /// Sign a vector of messages -> 80-byte signature.
  Uint8List bbsSign(
    Uint8List secretKey,
    Uint8List publicKey,
    Uint8List header,
    List<Uint8List> messages,
  ) {
    final sk = _toNative(secretKey),
        pk = _toNative(publicKey),
        h = _toNative(header);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
          )
        >('cryptolib_bbs_sign')(
          sk,
          secretKey.length,
          pk,
          publicKey.length,
          h,
          header.length,
          mp,
          ml,
          messages.length,
        ),
      );
    } finally {
      if (sk != nullptr) calloc.free(sk);
      if (pk != nullptr) calloc.free(pk);
      if (h != nullptr) {
        calloc.free(h);
      }
      _freeNativeList(mp, ml, messages.length);
    }
  }
}
