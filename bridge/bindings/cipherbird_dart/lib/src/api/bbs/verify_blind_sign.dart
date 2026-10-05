part of '../../cryptolib.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CryptoLib.
extension CryptoLibBbsVerifyBlindSign on CryptoLib {
  /// Verify a blind signature over [messages] + [committedMessages] using the
  /// [secretProverBlind] kept from [bbsBlindCommit].
  bool bbsVerifyBlindSign(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    List<Uint8List> messages,
    List<Uint8List> committedMessages,
    Uint8List secretProverBlind,
  ) {
    final pk = _toNative(publicKey),
        s = _toNative(signature),
        h = _toNative(header),
        spb = _toNative(secretProverBlind);
    final (mp, ml) = _toNativeList(messages);
    final (cm, cl) = _toNativeList(committedMessages);
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
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              Size,
              Pointer<Uint8>,
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
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_bbs_verify_blind_sign')(
            pk,
            publicKey.length,
            s,
            signature.length,
            h,
            header.length,
            mp,
            ml,
            messages.length,
            cm,
            cl,
            committedMessages.length,
            spb,
            secretProverBlind.length,
          ) ==
          1;
    } finally {
      for (final x in [pk, s, h, spb]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(mp, ml, messages.length);
      _freeNativeList(cm, cl, committedMessages.length);
    }
  }
}
