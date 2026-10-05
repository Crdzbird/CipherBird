part of '../../cryptolib.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CryptoLib.
extension CryptoLibBbsPseudonymSecrets on CryptoLib {
  /// Finalize nym_secrets = [proverNyms] with the last element +=
  /// [signerNymEntropy]. Returns concatenated 32-byte scalars.
  Uint8List bbsFinalizeNymSecrets(
    List<Uint8List> proverNyms,
    Uint8List signerNymEntropy,
  ) {
    final (pm, pl) = _toNativeList(proverNyms);
    final e = _toNative(signerNymEntropy);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_bbs_finalize_nym_secrets')(
          pm,
          pl,
          proverNyms.length,
          e,
          signerNymEntropy.length,
        ),
      );
    } finally {
      _freeNativeList(pm, pl, proverNyms.length);
      if (e != nullptr) {
        calloc.free(e);
      }
    }
  }

  /// Derive the deterministic pseudonym (48-byte compressed G1 point) for a
  /// context from the [nymSecrets].
  Uint8List bbsCalculatePseudonym(
    Uint8List contextId,
    List<Uint8List> nymSecrets,
  ) {
    final c = _toNative(contextId);
    final (nm, nl) = _toNativeList(nymSecrets);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Pointer<Uint8>>,
            Pointer<Size>,
            int,
          )
        >('cryptolib_bbs_calculate_pseudonym')(
          c,
          contextId.length,
          nm,
          nl,
          nymSecrets.length,
        ),
      );
    } finally {
      if (c != nullptr) {
        calloc.free(c);
      }
      _freeNativeList(nm, nl, nymSecrets.length);
    }
  }
}
