part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsProofVerify on CipherBird {
  /// Verify a selective-disclosure proof against the revealed messages.
  bool bbsProofVerify(
    Uint8List publicKey,
    Uint8List proof,
    Uint8List header,
    Uint8List ph,
    List<Uint8List> disclosedMessages,
    List<int> disclosedIndexes,
  ) {
    final pk = _toNative(publicKey),
        pr = _toNative(proof),
        h = _toNative(header),
        p = _toNative(ph);
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
              Pointer<Pointer<Uint8>>,
              Pointer<Size>,
              int,
              Pointer<Uint64>,
              int,
            )
          >('cryptolib_bbs_proof_verify')(
            pk,
            publicKey.length,
            pr,
            proof.length,
            h,
            header.length,
            p,
            ph.length,
            mp,
            ml,
            disclosedMessages.length,
            idx,
            disclosedIndexes.length,
          ) ==
          1;
    } finally {
      for (final x in [pk, pr, h, p]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(mp, ml, disclosedMessages.length);
      calloc.free(idx);
    }
  }

  Pointer<Uint64> _bbsU64(List<int> items) {
    final p = calloc<Uint64>(items.isEmpty ? 1 : items.length);
    for (var i = 0; i < items.length; i++) {
      p[i] = items[i];
    }
    return p;
  }
}
