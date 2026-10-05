part of '../../cipher_bird.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CipherBird.
extension CipherBirdBbsScalars on CipherBird {
  /// Deterministically map (msg, dst) to a canonical scalar in [0, r) - the BBS
  /// hash_to_scalar primitive. Use for a stable per-holder nym seed:
  /// nymSeed = bbsHashToScalar(memberSecret, dst).
  Uint8List bbsHashToScalar(Uint8List msg, Uint8List dst) {
    final m = _toNative(msg), d = _toNative(dst);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_bbs_hash_to_scalar')(m, msg.length, d, dst.length),
      );
    } finally {
      if (m != nullptr) {
        calloc.free(m);
      }
      if (d != nullptr) {
        calloc.free(d);
      }
    }
  }

  /// A fresh cryptographically-random canonical scalar in [0, r) (32 bytes BE).
  Uint8List bbsRandomScalar() {
    return _checkBufResult(
      _lib.lookupFunction<
        CryptoBufferResult Function(),
        CryptoBufferResult Function()
      >('cryptolib_bbs_random_scalar')(),
    );
  }
}
