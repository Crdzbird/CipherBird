part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsProofGenWithPseudonym on CipherBird {
  /// Generate a pseudonym-bound selective-disclosure proof. Returns
  /// (proof, pseudonym). Disclosed index lists are 0-based into the signer and
  /// committed message vectors respectively.
  (Uint8List, Uint8List) bbsProofGenWithPseudonym(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    Uint8List ph,
    Uint8List contextId,
    List<Uint8List> signerMessages,
    List<Uint8List> committedMessages,
    Uint8List secretProverBlind,
    List<Uint8List> nymSecrets,
    List<int> disclosedSignerIndexes,
    List<int> disclosedCommittedIndexes,
  ) {
    final pk = _toNative(publicKey),
        s = _toNative(signature),
        h = _toNative(header),
        p = _toNative(ph);
    final c = _toNative(contextId), spb = _toNative(secretProverBlind);
    final (sm, sl) = _toNativeList(signerMessages);
    final (cm, cl) = _toNativeList(committedMessages);
    final (nm, nl) = _toNativeList(nymSecrets);
    final si = _bbsU64(disclosedSignerIndexes),
        ci = _bbsU64(disclosedCommittedIndexes);
    final nymOut = calloc<CryptoBuffer>();
    try {
      final proof = _checkBufResult(
        _lib.lookupFunction<_BbsProofGenWithNymC, _BbsProofGenWithNymDart>(
          'cryptolib_bbs_proof_gen_with_pseudonym',
        )(
          pk,
          publicKey.length,
          s,
          signature.length,
          h,
          header.length,
          p,
          ph.length,
          c,
          contextId.length,
          sm,
          sl,
          signerMessages.length,
          cm,
          cl,
          committedMessages.length,
          spb,
          secretProverBlind.length,
          nm,
          nl,
          nymSecrets.length,
          si,
          disclosedSignerIndexes.length,
          ci,
          disclosedCommittedIndexes.length,
          nymOut,
        ),
      );
      return (proof, _copyBuf(nymOut.ref));
    } finally {
      for (final x in [pk, s, h, p, c, spb]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(sm, sl, signerMessages.length);
      _freeNativeList(cm, cl, committedMessages.length);
      _freeNativeList(nm, nl, nymSecrets.length);
      calloc.free(si);
      calloc.free(ci);
      calloc.free(nymOut);
    }
  }
}
