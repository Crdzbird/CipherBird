part of '../cryptolib.dart';

// ── BBS — multi-message signatures + selective disclosure (BLS12-381) ─────────
// Sign a vector of messages; derive a zero-knowledge proof revealing only a
// chosen subset while proving a valid signature covers all of them — the core
// primitive behind anonymous credentials (W3C Verifiable Credentials).

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CryptoLib.
extension CryptoLibBbs on CryptoLib {
  /// KeyGen from key material (>= 32 B) + optional key info. Throws on failure.
  KeyPairResult bbsKeygen(Uint8List keyMaterial, {Uint8List? keyInfo}) {
    final km = _toNative(keyMaterial);
    final ki = keyInfo != null ? _toNative(keyInfo) : nullptr;
    try {
      final r = _extractKeyPair(_lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_bbs_keygen')(
          km, keyMaterial.length, ki, keyInfo?.length ?? 0));
      if (r.publicKey.isEmpty) throw Exception('cryptolib: bbs keygen failed (key material must be >= 32 bytes)');
      return r;
    } finally { if (km != nullptr) calloc.free(km); if (ki != nullptr) calloc.free(ki); }
  }

  /// Derive the 96-byte public key from a 32-byte secret key.
  Uint8List bbsSkToPk(Uint8List secretKey) {
    final p = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>('cryptolib_bbs_sk_to_pk')(p, secretKey.length));
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Sign a vector of messages → 80-byte signature.
  Uint8List bbsSign(Uint8List secretKey, Uint8List publicKey, Uint8List header, List<Uint8List> messages) {
    final sk = _toNative(secretKey), pk = _toNative(publicKey), h = _toNative(header);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int)>('cryptolib_bbs_sign')(
          sk, secretKey.length, pk, publicKey.length, h, header.length, mp, ml, messages.length));
    } finally {
      if (sk != nullptr) calloc.free(sk); if (pk != nullptr) calloc.free(pk); if (h != nullptr) calloc.free(h);
      _freeNativeList(mp, ml, messages.length);
    }
  }

  /// Verify a signature over a vector of messages.
  bool bbsVerify(Uint8List publicKey, Uint8List signature, Uint8List header, List<Uint8List> messages) {
    final pk = _toNative(publicKey), s = _toNative(signature), h = _toNative(header);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int)>('cryptolib_bbs_verify')(
          pk, publicKey.length, s, signature.length, h, header.length, mp, ml, messages.length) == 1;
    } finally {
      if (pk != nullptr) calloc.free(pk); if (s != nullptr) calloc.free(s); if (h != nullptr) calloc.free(h);
      _freeNativeList(mp, ml, messages.length);
    }
  }

  /// Derive a selective-disclosure proof. `messages` is the FULL signed vector;
  /// `disclosedIndexes` (0-based) selects which to reveal.
  Uint8List bbsProofGen(Uint8List publicKey, Uint8List signature, Uint8List header, Uint8List ph,
      List<Uint8List> messages, List<int> disclosedIndexes) {
    final pk = _toNative(publicKey), s = _toNative(signature), h = _toNative(header), p = _toNative(ph);
    final (mp, ml) = _toNativeList(messages);
    final idx = _bbsU64(disclosedIndexes);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint64>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint64>, int)>('cryptolib_bbs_proof_gen')(
          pk, publicKey.length, s, signature.length, h, header.length, p, ph.length,
          mp, ml, messages.length, idx, disclosedIndexes.length));
    } finally {
      for (final x in [pk, s, h, p]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(mp, ml, messages.length);
      calloc.free(idx);
    }
  }

  /// Verify a selective-disclosure proof against the revealed messages.
  bool bbsProofVerify(Uint8List publicKey, Uint8List proof, Uint8List header, Uint8List ph,
      List<Uint8List> disclosedMessages, List<int> disclosedIndexes) {
    final pk = _toNative(publicKey), pr = _toNative(proof), h = _toNative(header), p = _toNative(ph);
    final (mp, ml) = _toNativeList(disclosedMessages);
    final idx = _bbsU64(disclosedIndexes);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint64>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint64>, int)>('cryptolib_bbs_proof_verify')(
          pk, publicKey.length, pr, proof.length, h, header.length, p, ph.length,
          mp, ml, disclosedMessages.length, idx, disclosedIndexes.length) == 1;
    } finally {
      for (final x in [pk, pr, h, p]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(mp, ml, disclosedMessages.length);
      calloc.free(idx);
    }
  }

  Pointer<Uint64> _bbsU64(List<int> items) {
    final p = calloc<Uint64>(items.isEmpty ? 1 : items.length);
    for (var i = 0; i < items.length; i++) { p[i] = items[i]; }
    return p;
  }
}
