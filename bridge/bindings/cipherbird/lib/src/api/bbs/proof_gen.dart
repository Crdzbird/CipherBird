part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsProofGen on CipherBird {
  /// Derive a selective-disclosure proof. `messages` is the FULL signed vector;
  /// `disclosedIndexes` (0-based) selects which to reveal.
  Uint8List bbsProofGen(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    Uint8List ph,
    List<Uint8List> messages,
    List<int> disclosedIndexes,
  ) {
    final pk = _toNative(publicKey),
        s = _toNative(signature),
        h = _toNative(header),
        p = _toNative(ph);
    final (mp, ml) = _toNativeList(messages);
    final idx = _bbsU64(disclosedIndexes);
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
            Pointer<Uint64>,
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
            Pointer<Uint64>,
            int,
          )
        >('cryptolib_bbs_proof_gen')(
          pk,
          publicKey.length,
          s,
          signature.length,
          h,
          header.length,
          p,
          ph.length,
          mp,
          ml,
          messages.length,
          idx,
          disclosedIndexes.length,
        ),
      );
    } finally {
      for (final x in [pk, s, h, p]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(mp, ml, messages.length);
      calloc.free(idx);
    }
  }
}
