part of '../cryptolib.dart';

// ── ECVRF — Verifiable Random Function (RFC 9381) ─────────────────────────────
// ECVRF-EDWARDS25519-SHA512-TAI. A public-key PRF: prove(sk, alpha) yields a
// unique, unpredictable 64-byte output plus an 80-byte proof anyone can verify
// with the public key. Verifiable lotteries, leader election, randomness beacons.

/// ECVRF (RFC 9381) methods on CryptoLib.
extension CryptoLibEcvrf on CryptoLib {
  /// ECVRF key pair (pk 32 B, sk = 32-byte seed).
  KeyPairResult ecvrfKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>('cryptolib_ecvrf_keygen')());

  /// Derive the public key Y = x·B from a 32-byte secret seed.
  Uint8List ecvrfPublicKey(Uint8List secretKey) {
    final p = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>('cryptolib_ecvrf_public_key')(p, secretKey.length));
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Prove: returns the 80-byte proof for (sk, alpha).
  Uint8List ecvrfProve(Uint8List secretKey, Uint8List alpha) {
    final ps = _toNative(secretKey), pa = _toNative(alpha);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_ecvrf_prove')(
          ps, secretKey.length, pa, alpha.length));
    } finally { if (ps != nullptr) calloc.free(ps); if (pa != nullptr) calloc.free(pa); }
  }

  /// proof_to_hash: returns the 64-byte VRF output beta for a proof.
  Uint8List ecvrfProofToHash(Uint8List proof) {
    final p = _toNative(proof);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>('cryptolib_ecvrf_proof_to_hash')(p, proof.length));
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Verify: returns the 64-byte beta on success; throws if the proof is invalid.
  Uint8List ecvrfVerify(Uint8List publicKey, Uint8List alpha, Uint8List proof) {
    final pk = _toNative(publicKey), pa = _toNative(alpha), pi = _toNative(proof);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_ecvrf_verify')(
          pk, publicKey.length, pa, alpha.length, pi, proof.length));
    } finally {
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
      if (pi != nullptr) calloc.free(pi);
    }
  }
}
