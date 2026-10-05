part of '../../cryptolib.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CryptoLib.
extension CryptoLibBbsVerify on CryptoLib {
  /// Verify a signature over a vector of messages.
  bool bbsVerify(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    List<Uint8List> messages,
  ) {
    final pk = _toNative(publicKey),
        s = _toNative(signature),
        h = _toNative(header);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _lib.lookupFunction<
            Int32 Function(
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
            int Function(
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
          >('cryptolib_bbs_verify')(
            pk,
            publicKey.length,
            s,
            signature.length,
            h,
            header.length,
            mp,
            ml,
            messages.length,
          ) ==
          1;
    } finally {
      if (pk != nullptr) calloc.free(pk);
      if (s != nullptr) calloc.free(s);
      if (h != nullptr) {
        calloc.free(h);
      }
      _freeNativeList(mp, ml, messages.length);
    }
  }
}
