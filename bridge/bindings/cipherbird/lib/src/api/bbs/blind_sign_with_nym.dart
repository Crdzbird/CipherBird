part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsBlindSignWithNym on CipherBird {
  /// Blind-sign over the commitment + signer [messages], folding
  /// [signerNymEntropy] into the last nym slot. Returns an 80-byte signature.
  Uint8List bbsBlindSignWithNym(
    Uint8List secretKey,
    Uint8List publicKey,
    Uint8List commitmentWithProof,
    Uint8List header,
    List<Uint8List> messages,
    Uint8List signerNymEntropy,
    int lengthNymVector,
  ) {
    final sk = _toNative(secretKey),
        pk = _toNative(publicKey),
        cwp = _toNative(commitmentWithProof);
    final h = _toNative(header), e = _toNative(signerNymEntropy);
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
            Pointer<Uint8>,
            Size,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
            Pointer<Uint8>,
            Size,
            Uint64,
          ),
          CryptoBufferResult Function(
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
            Pointer<Uint8>,
            int,
            int,
          )
        >('cryptolib_bbs_blind_sign_with_nym')(
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
          e,
          signerNymEntropy.length,
          lengthNymVector,
        ),
      );
    } finally {
      for (final x in [sk, pk, cwp, h, e]) {
        if (x != nullptr) calloc.free(x);
      }
      _freeNativeList(mp, ml, messages.length);
    }
  }
}
