part of '../../cryptolib.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CryptoLib.
extension CryptoLibBbsProofVerifyWithPseudonym on CryptoLib {
  /// Verify a pseudonym-bound proof. [disclosedMessages]/[disclosedIndexes] are
  /// the COMBINED signer+committed disclosures (committed index j passed as j+L+1).
  bool bbsProofVerifyWithPseudonym(
    Uint8List publicKey,
    Uint8List proof,
    Uint8List header,
    Uint8List ph,
    Uint8List contextId,
    Uint8List pseudonym,
    int L,
    int lengthNymVector,
    List<Uint8List> disclosedMessages,
    List<int> disclosedIndexes,
  ) {
    final pk = _toNative(publicKey),
        pr = _toNative(proof),
        h = _toNative(header),
        p = _toNative(ph);
    final c = _toNative(contextId), n = _toNative(pseudonym);
    final (mp, ml) = _toNativeList(disclosedMessages);
    final idx = _bbsU64(disclosedIndexes);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Uint64,
              Uint64,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              Size,
              Pointer<Uint64>,
              Size,
            ),
            int Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              int,
              int,
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              int,
              Pointer<Uint64>,
              int,
            )
          >('cryptolib_bbs_proof_verify_with_pseudonym')(
            pk,
            publicKey.length,
            pr,
            proof.length,
            h,
            header.length,
            p,
            ph.length,
            c,
            contextId.length,
            n,
            pseudonym.length,
            L,
            lengthNymVector,
            mp,
            ml,
            disclosedMessages.length,
            idx,
            disclosedIndexes.length,
          ) ==
          1;
    } finally {
      for (final x in [pk, pr, h, p, c, n]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(mp, ml, disclosedMessages.length);
      calloc.free(idx);
    }
  }
}
