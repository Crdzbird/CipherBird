part of '../../cipher_bird.dart';

/// EVM / Bitcoin interop: Keccak-256, RIPEMD-160 and secp256k1 ECDSA.
extension CipherBirdSecp256k1Verify on CipherBird {
  /// Verify a 64-byte [sig] (r‖s) over a 32-byte [digest]. [publicKey] is 33 or
  /// 65 bytes. Low-S enforced (EIP-2 / BIP-62). Returns true if valid.
  bool secp256k1Verify(Uint8List digest, Uint8List sig, Uint8List publicKey) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 verify: digest must be 32 bytes');
    }
    final dp = _toNative(digest),
        sgp = _toNative(sig),
        pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              Pointer<Uint8>,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_secp256k1_verify')(
            dp,
            sgp,
            sig.length,
            pp,
            publicKey.length,
          ) ==
          1;
    } finally {
      if (dp != nullptr) {
        calloc.free(dp);
      }
      if (sgp != nullptr) {
        calloc.free(sgp);
      }
      if (pp != nullptr) {
        calloc.free(pp);
      }
    }
  }

  /// Recover the 65-byte uncompressed public key from a 32-byte [digest] and a
  /// 65-byte recoverable [sig65] (r‖s‖recovery_id). Ethereum's ecrecover.
  Uint8List secp256k1Recover(Uint8List digest, Uint8List sig65) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 recover: digest must be 32 bytes');
    }
    if (sig65.length != 65) {
      throw ArgumentError(
        'secp256k1 recover: signature must be 65 bytes (r‖s‖recid)',
      );
    }
    final dp = _toNative(digest), sp = _toNative(sig65);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Uint8>, Pointer<Uint8>),
          CipherBirdBufferResult Function(Pointer<Uint8>, Pointer<Uint8>)
        >('cryptolib_secp256k1_recover')(dp, sp),
      );
    } finally {
      if (dp != nullptr) calloc.free(dp);
      if (sp != nullptr) calloc.free(sp);
    }
  }
}
