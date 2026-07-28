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

  // ── Per-verifier pseudonyms + blind issuance ────────────────────────────────
  // draft-irtf-cfrg-bbs-per-verifier-linkability-02. The pseudonym ciphersuite
  // is applied internally. Scalar inputs (proverNyms, nymSecrets,
  // secretProverBlind, signerNymEntropy) are 32-byte big-endian.

  /// Commit to [committedMessages] plus [proverNyms] (secret scalars the issuer
  /// must not learn). Returns (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) bbsCommitWithNym(List<Uint8List> committedMessages, List<Uint8List> proverNyms) {
    final (cm, cl) = _toNativeList(committedMessages);
    final (pm, pl) = _toNativeList(proverNyms);
    final spb = calloc<CryptoBuffer>();
    try {
      final cwp = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<CryptoBuffer>)>('cryptolib_bbs_commit_with_nym')(
          cm, cl, committedMessages.length, pm, pl, proverNyms.length, spb));
      return (cwp, _copyBuf(spb.ref)); // _copyBuf frees the inner allocation
    } finally {
      _freeNativeList(cm, cl, committedMessages.length);
      _freeNativeList(pm, pl, proverNyms.length);
      calloc.free(spb);
    }
  }

  /// Blind-sign over the commitment + signer [messages], folding
  /// [signerNymEntropy] into the last nym slot. Returns an 80-byte signature.
  Uint8List bbsBlindSignWithNym(Uint8List secretKey, Uint8List publicKey, Uint8List commitmentWithProof,
      Uint8List header, List<Uint8List> messages, Uint8List signerNymEntropy, int lengthNymVector) {
    final sk = _toNative(secretKey), pk = _toNative(publicKey), cwp = _toNative(commitmentWithProof);
    final h = _toNative(header), e = _toNative(signerNymEntropy);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint8>, Size, Uint64),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint8>, int, int)>('cryptolib_bbs_blind_sign_with_nym')(
          sk, secretKey.length, pk, publicKey.length, cwp, commitmentWithProof.length,
          h, header.length, mp, ml, messages.length, e, signerNymEntropy.length, lengthNymVector));
    } finally {
      for (final x in [sk, pk, cwp, h, e]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(mp, ml, messages.length);
    }
  }

  /// Finalize nym_secrets = [proverNyms] with the last element +=
  /// [signerNymEntropy]. Returns concatenated 32-byte scalars.
  Uint8List bbsFinalizeNymSecrets(List<Uint8List> proverNyms, Uint8List signerNymEntropy) {
    final (pm, pl) = _toNativeList(proverNyms);
    final e = _toNative(signerNymEntropy);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint8>, int)>('cryptolib_bbs_finalize_nym_secrets')(
          pm, pl, proverNyms.length, e, signerNymEntropy.length));
    } finally {
      _freeNativeList(pm, pl, proverNyms.length);
      if (e != nullptr) calloc.free(e);
    }
  }

  /// Derive the deterministic pseudonym (48-byte compressed G1 point) for a
  /// context from the [nymSecrets].
  Uint8List bbsCalculatePseudonym(Uint8List contextId, List<Uint8List> nymSecrets) {
    final c = _toNative(contextId);
    final (nm, nl) = _toNativeList(nymSecrets);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int)>('cryptolib_bbs_calculate_pseudonym')(
          c, contextId.length, nm, nl, nymSecrets.length));
    } finally {
      if (c != nullptr) calloc.free(c);
      _freeNativeList(nm, nl, nymSecrets.length);
    }
  }

  /// Generate a pseudonym-bound selective-disclosure proof. Returns
  /// (proof, pseudonym). Disclosed index lists are 0-based into the signer and
  /// committed message vectors respectively.
  (Uint8List, Uint8List) bbsProofGenWithPseudonym(Uint8List publicKey, Uint8List signature, Uint8List header,
      Uint8List ph, Uint8List contextId, List<Uint8List> signerMessages, List<Uint8List> committedMessages,
      Uint8List secretProverBlind, List<Uint8List> nymSecrets,
      List<int> disclosedSignerIndexes, List<int> disclosedCommittedIndexes) {
    final pk = _toNative(publicKey), s = _toNative(signature), h = _toNative(header), p = _toNative(ph);
    final c = _toNative(contextId), spb = _toNative(secretProverBlind);
    final (sm, sl) = _toNativeList(signerMessages);
    final (cm, cl) = _toNativeList(committedMessages);
    final (nm, nl) = _toNativeList(nymSecrets);
    final si = _bbsU64(disclosedSignerIndexes), ci = _bbsU64(disclosedCommittedIndexes);
    final nymOut = calloc<CryptoBuffer>();
    try {
      final proof = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint64>, Size, Pointer<Uint64>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint64>, int, Pointer<Uint64>, int, Pointer<CryptoBuffer>)>('cryptolib_bbs_proof_gen_with_pseudonym')(
          pk, publicKey.length, s, signature.length, h, header.length, p, ph.length, c, contextId.length,
          sm, sl, signerMessages.length, cm, cl, committedMessages.length, spb, secretProverBlind.length,
          nm, nl, nymSecrets.length, si, disclosedSignerIndexes.length, ci, disclosedCommittedIndexes.length, nymOut));
      return (proof, _copyBuf(nymOut.ref)); // _copyBuf frees the inner allocation
    } finally {
      for (final x in [pk, s, h, p, c, spb]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(sm, sl, signerMessages.length);
      _freeNativeList(cm, cl, committedMessages.length);
      _freeNativeList(nm, nl, nymSecrets.length);
      calloc.free(si); calloc.free(ci); calloc.free(nymOut);
    }
  }

  /// Verify a pseudonym-bound proof. [disclosedMessages]/[disclosedIndexes] are
  /// the COMBINED signer+committed disclosures (committed index j passed as j+L+1).
  bool bbsProofVerifyWithPseudonym(Uint8List publicKey, Uint8List proof, Uint8List header, Uint8List ph,
      Uint8List contextId, Uint8List pseudonym, int L, int lengthNymVector,
      List<Uint8List> disclosedMessages, List<int> disclosedIndexes) {
    final pk = _toNative(publicKey), pr = _toNative(proof), h = _toNative(header), p = _toNative(ph);
    final c = _toNative(contextId), n = _toNative(pseudonym);
    final (mp, ml) = _toNativeList(disclosedMessages);
    final idx = _bbsU64(disclosedIndexes);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Uint64, Uint64, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint64>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint64>, int)>('cryptolib_bbs_proof_verify_with_pseudonym')(
          pk, publicKey.length, pr, proof.length, h, header.length, p, ph.length,
          c, contextId.length, n, pseudonym.length, L, lengthNymVector,
          mp, ml, disclosedMessages.length, idx, disclosedIndexes.length) == 1;
    } finally {
      for (final x in [pk, pr, h, p, c, n]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(mp, ml, disclosedMessages.length);
      calloc.free(idx);
    }
  }

  // ── Standalone blind issuance (draft-irtf-cfrg-bbs-blind-signatures-02, no
  // pseudonyms). The blind-interface ciphersuite is applied internally.
  // secretProverBlind is a 32-byte big-endian scalar.

  /// Commit to [committedMessages] (which the signer never learns). Returns
  /// (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) bbsBlindCommit(List<Uint8List> committedMessages) {
    final (cm, cl) = _toNativeList(committedMessages);
    final spb = calloc<CryptoBuffer>();
    try {
      final cwp = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<CryptoBuffer>)>('cryptolib_bbs_blind_commit')(
          cm, cl, committedMessages.length, spb));
      return (cwp, _copyBuf(spb.ref)); // _copyBuf frees the inner allocation
    } finally {
      _freeNativeList(cm, cl, committedMessages.length);
      calloc.free(spb);
    }
  }

  /// Blind-sign over the commitment + signer [messages] → 80-byte signature.
  Uint8List bbsBlindSign(Uint8List secretKey, Uint8List publicKey, Uint8List commitmentWithProof,
      Uint8List header, List<Uint8List> messages) {
    final sk = _toNative(secretKey), pk = _toNative(publicKey), cwp = _toNative(commitmentWithProof), h = _toNative(header);
    final (mp, ml) = _toNativeList(messages);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int)>('cryptolib_bbs_blind_sign')(
          sk, secretKey.length, pk, publicKey.length, cwp, commitmentWithProof.length,
          h, header.length, mp, ml, messages.length));
    } finally {
      for (final x in [sk, pk, cwp, h]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(mp, ml, messages.length);
    }
  }

  /// Verify a blind signature over [messages] + [committedMessages] using the
  /// [secretProverBlind] kept from [bbsBlindCommit].
  bool bbsVerifyBlindSign(Uint8List publicKey, Uint8List signature, Uint8List header,
      List<Uint8List> messages, List<Uint8List> committedMessages, Uint8List secretProverBlind) {
    final pk = _toNative(publicKey), s = _toNative(signature), h = _toNative(header), spb = _toNative(secretProverBlind);
    final (mp, ml) = _toNativeList(messages);
    final (cm, cl) = _toNativeList(committedMessages);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint8>, int)>('cryptolib_bbs_verify_blind_sign')(
          pk, publicKey.length, s, signature.length, h, header.length,
          mp, ml, messages.length, cm, cl, committedMessages.length, spb, secretProverBlind.length) == 1;
    } finally {
      for (final x in [pk, s, h, spb]) { if (x != nullptr) calloc.free(x); }
      _freeNativeList(mp, ml, messages.length);
      _freeNativeList(cm, cl, committedMessages.length);
    }
  }

  // ── Canonical scalar helpers (issue #5). Both return a 32-byte big-endian
  // value strictly < r, ready to feed the pseudonym / blind-issuance API.

  /// Deterministically map (msg, dst) to a canonical scalar in [0, r) — the BBS
  /// hash_to_scalar primitive. Use for a stable per-holder nym seed:
  /// nymSeed = bbsHashToScalar(memberSecret, dst).
  Uint8List bbsHashToScalar(Uint8List msg, Uint8List dst) {
    final m = _toNative(msg), d = _toNative(dst);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_bbs_hash_to_scalar')(
          m, msg.length, d, dst.length));
    } finally {
      if (m != nullptr) calloc.free(m);
      if (d != nullptr) calloc.free(d);
    }
  }

  /// A fresh cryptographically-random canonical scalar in [0, r) (32 bytes BE).
  Uint8List bbsRandomScalar() {
    return _checkBufResult(_lib.lookupFunction<
        CryptoBufferResult Function(),
        CryptoBufferResult Function()>('cryptolib_bbs_random_scalar')());
  }
}
