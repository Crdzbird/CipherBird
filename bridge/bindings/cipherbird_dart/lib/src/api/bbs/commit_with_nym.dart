part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsCommitWithNym on CipherBird {
  /// Commit to [committedMessages] plus [proverNyms] (secret scalars the issuer
  /// must not learn). Returns (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) bbsCommitWithNym(
    List<Uint8List> committedMessages,
    List<Uint8List> proverNyms,
  ) {
    final (cm, cl) = _toNativeList(committedMessages);
    final (pm, pl) = _toNativeList(proverNyms);
    final spb = calloc<CryptoBuffer>();
    try {
      final cwp = _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
            Pointer<CryptoBuffer>,
          ),
          CryptoBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
            Pointer<CryptoBuffer>,
          )
        >('cryptolib_bbs_commit_with_nym')(
          cm,
          cl,
          committedMessages.length,
          pm,
          pl,
          proverNyms.length,
          spb,
        ),
      );
      return (cwp, _copyBuf(spb.ref));
    } finally {
      _freeNativeList(cm, cl, committedMessages.length);
      _freeNativeList(pm, pl, proverNyms.length);
      calloc.free(spb);
    }
  }
}
