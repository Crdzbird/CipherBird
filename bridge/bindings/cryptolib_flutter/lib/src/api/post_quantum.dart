part of '../cryptolib.dart';

/// PostQuantum operations.
extension CryptoLibPostQuantum on CryptoLib {
  // ── Post-Quantum (ML-KEM / ML-DSA / SLH-DSA) ──────────────────────────────

  KeyPairResult mlKemKeygen(MlKemLevel level) => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(Int32), CryptoKeyPair Function(int)>(
          'cryptolib_ml_kem_keygen')(level.value));

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) mlKemEncapsulate(Uint8List publicKey, MlKemLevel level) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib.lookupFunction<
          CryptoKemEncapsResult Function(Pointer<Uint8>, Size, Int32, Pointer<Pointer<Utf8>>),
          CryptoKemEncapsResult Function(Pointer<Uint8>, int, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_ml_kem_encapsulate')(pp, publicKey.length, level.value, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      return (_copyBuf(r.ciphertext), _copyBuf(r.sharedSecret));
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  Uint8List mlKemDecapsulate(Uint8List ciphertext, Uint8List secretKey, MlKemLevel level) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_ml_kem_decapsulate')(cp, ciphertext.length, sp, secretKey.length, level.value));
    } finally { if (cp != nullptr) calloc.free(cp); if (sp != nullptr) calloc.free(sp); }
  }

  // ── Hybrid KEM (X25519 + ML-KEM-768) ──────────────────────────────────────

  KeyPairResult hybridKemKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_hybrid_kem_keygen')());

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) hybridKemEncapsulate(Uint8List publicKey) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib.lookupFunction<
          CryptoKemEncapsResult Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          CryptoKemEncapsResult Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_hybrid_kem_encapsulate')(pp, publicKey.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      return (_copyBuf(r.ciphertext), _copyBuf(r.sharedSecret));
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  Uint8List hybridKemDecapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hybrid_kem_decapsulate')(cp, ciphertext.length, sp, secretKey.length));
    } finally { if (cp != nullptr) calloc.free(cp); if (sp != nullptr) calloc.free(sp); }
  }

  // ── Hybrid KEM (X25519 + sntrup761) ───────────────────────────────────────
  // Second hybrid using NTRU Prime — a different lattice family for diversity.

  KeyPairResult sntrupX25519Keygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_sntrup_x25519_keygen')());

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) sntrupX25519Encapsulate(Uint8List publicKey) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib.lookupFunction<
          CryptoKemEncapsResult Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          CryptoKemEncapsResult Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_sntrup_x25519_encapsulate')(pp, publicKey.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      return (_copyBuf(r.ciphertext), _copyBuf(r.sharedSecret));
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  Uint8List sntrupX25519Decapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_sntrup_x25519_decapsulate')(cp, ciphertext.length, sp, secretKey.length));
    } finally { if (cp != nullptr) calloc.free(cp); if (sp != nullptr) calloc.free(sp); }
  }

  KeyPairResult mlDsaKeygen(MlDsaLevel level) => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(Int32), CryptoKeyPair Function(int)>(
          'cryptolib_ml_dsa_keygen')(level.value));

  Uint8List mlDsaSign(Uint8List msg, Uint8List secretKey, MlDsaLevel level) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_ml_dsa_sign')(mp, msg.length, sp, secretKey.length, level.value));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool mlDsaVerify(Uint8List msg, Uint8List sig, Uint8List publicKey, MlDsaLevel level) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_ml_dsa_verify')(mp, msg.length, sgp, sig.length, pp, publicKey.length, level.value) == 1;
    } finally { if (mp != nullptr) calloc.free(mp); if (sgp != nullptr) calloc.free(sgp); if (pp != nullptr) calloc.free(pp); }
  }

  KeyPairResult slhDsaKeygen(SlhDsaLevel level, SlhDsaHash hash) => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(Int32, Int32), CryptoKeyPair Function(int, int)>(
          'cryptolib_slh_dsa_keygen')(level.value, hash.value));

  Uint8List slhDsaSign(Uint8List msg, Uint8List secretKey, SlhDsaLevel level, SlhDsaHash hash) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int, int)>(
          'cryptolib_slh_dsa_sign')(mp, msg.length, sp, secretKey.length, level.value, hash.value));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool slhDsaVerify(Uint8List msg, Uint8List sig, Uint8List publicKey, SlhDsaLevel level, SlhDsaHash hash) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32, Int32),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int, int)>(
          'cryptolib_slh_dsa_verify')(mp, msg.length, sgp, sig.length, pp, publicKey.length, level.value, hash.value) == 1;
    } finally { if (mp != nullptr) calloc.free(mp); if (sgp != nullptr) calloc.free(sgp); if (pp != nullptr) calloc.free(pp); }
  }


  // ── Hybrid signature (Ed25519 + ML-DSA-65) ────────────────────────────────
  // Both classical and post-quantum signatures must verify. Keys and the
  // signature are concatenated: ed25519_part || ml_dsa_part.

  KeyPairResult hybridSigKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_hybrid_sig_keygen')());

  Uint8List hybridSigSign(Uint8List msg, Uint8List secretKey) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hybrid_sig_sign')(mp, msg.length, sp, secretKey.length));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool hybridSigVerify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hybrid_sig_verify')(
              mp, msg.length, sgp, sig.length, pp, publicKey.length) == 1;
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }
}
