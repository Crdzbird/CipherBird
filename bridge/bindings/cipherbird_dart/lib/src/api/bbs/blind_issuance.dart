part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsBlindIssuance on CipherBird {
  /// Commit to [committedMessages] (which the signer never learns). Returns
  /// (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) bbsBlindCommit(List<Uint8List> committedMessages) {
    final (cm, cl) = _toNativeList(committedMessages);
    final spb = calloc<CipherBirdBuffer>();
    try {
      final cwp = _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
            Pointer<CipherBirdBuffer>,
          ),
          CipherBirdBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
            Pointer<CipherBirdBuffer>,
          )
        >('cryptolib_bbs_blind_commit')(cm, cl, committedMessages.length, spb),
      );
      return (cwp, _copyBuf(spb.ref));
    } finally {
      _freeNativeList(cm, cl, committedMessages.length);
      calloc.free(spb);
    }
  }

  /// Blind-sign over the commitment + signer [messages] -> 80-byte signature.
  Uint8List bbsBlindSign(
    Uint8List secretKey,
    Uint8List publicKey,
    Uint8List commitmentWithProof,
    Uint8List header,
    List<Uint8List> messages,
  ) {
    final sk = _toNative(secretKey),
        pk = _toNative(publicKey),
        cwp = _toNative(commitmentWithProof),
        h = _toNative(header);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
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
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
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
        >('cryptolib_bbs_blind_sign')(
          sk,
          secretKey.length,
          pk,
          publicKey.length,
          cwp,
          commitmentWithProof.length,
          h,
          header.length,
          mp,
          ml,
          messages.length,
        ),
      );
    } finally {
      for (final x in [sk, pk, cwp, h]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(mp, ml, messages.length);
    }
  }
}
