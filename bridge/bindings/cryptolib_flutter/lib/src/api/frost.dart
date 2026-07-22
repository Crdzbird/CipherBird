part of '../cryptolib.dart';

// ── FROST(Ed25519, SHA-512) — t-of-n threshold signatures (RFC 9591) ──────────
// t of n parties jointly produce ONE ordinary Ed25519 signature: no single party
// can sign, any t can, and the result verifies with standard Ed25519 against the
// group public key. Two rounds: everyone commits, then everyone signs over the
// message + full commitment set, and a coordinator aggregates the shares.

/// FROST trusted-dealer output: the group public key plus per-participant
/// shares. Share i (0-based) has FROST identifier i+1. Keep [secretShares]
/// private; distribute one to each participant.
class FrostKeyGen {
  final Uint8List groupPublicKey;
  final List<Uint8List> secretShares; // n × 32 B (secret scalars)
  final List<Uint8List> publicShares; // n × 32 B (points, for verifyShare)
  FrostKeyGen(this.groupPublicKey, this.secretShares, this.publicShares);
}

/// A participant's public round-1 commitment.
class FrostCommitment {
  final int identifier;
  final Uint8List hiding; // 32 B point
  final Uint8List binding; // 32 B point
  FrostCommitment(this.identifier, this.hiding, this.binding);
}

/// A participant's secret round-1 nonces (never share these).
class FrostNonces {
  final Uint8List hiding; // 32 B scalar
  final Uint8List binding; // 32 B scalar
  FrostNonces(this.hiding, this.binding);
}

// Copy a CryptoBuffer's bytes WITHOUT freeing it (the owning struct's *_free
// releases the whole native allocation in one call).
Uint8List _frostCopy(CryptoBuffer buf) {
  if (buf.data == nullptr || buf.len == 0) return Uint8List(0);
  final out = Uint8List(buf.len);
  out.setAll(0, buf.data.asTypedList(buf.len));
  return out;
}

/// FROST threshold-signature methods on CryptoLib.
extension CryptoLibFrost on CryptoLib {
  /// Trusted-dealer split: any [t] of [n] shares can sign. Share i (0-based) has
  /// FROST identifier i+1. Output verifies with standard Ed25519 verification.
  FrostKeyGen frostKeygen(int n, int t) {
    final kg = _lib.lookupFunction<
        CryptoFrostKeyGen Function(Uint16, Uint16),
        CryptoFrostKeyGen Function(int, int)>('cryptolib_frost_keygen')(n, t);
    if (kg.error != nullptr) {
      final m = kg.error.toDartString();
      _frostKeygenFree(kg);
      throw Exception(m);
    }
    final count = kg.count;
    final gpk = _frostCopy(kg.groupPublicKey);
    final secs = _frostCopy(kg.secretShares);
    final pubs = _frostCopy(kg.publicShares);
    _frostKeygenFree(kg);
    final secretShares = <Uint8List>[];
    final publicShares = <Uint8List>[];
    for (var i = 0; i < count; i++) {
      secretShares.add(Uint8List.sublistView(secs, i * 32, i * 32 + 32));
      publicShares.add(Uint8List.sublistView(pubs, i * 32, i * 32 + 32));
    }
    return FrostKeyGen(gpk, secretShares, publicShares);
  }

  void _frostKeygenFree(CryptoFrostKeyGen kg) {
    final p = calloc<CryptoFrostKeyGen>();
    p.ref.groupPublicKey.data = kg.groupPublicKey.data;
    p.ref.groupPublicKey.len = kg.groupPublicKey.len;
    p.ref.secretShares.data = kg.secretShares.data;
    p.ref.secretShares.len = kg.secretShares.len;
    p.ref.publicShares.data = kg.publicShares.data;
    p.ref.publicShares.len = kg.publicShares.len;
    p.ref.count = kg.count;
    p.ref.error = kg.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoFrostKeyGen>),
        void Function(Pointer<CryptoFrostKeyGen>)>('cryptolib_frost_keygen_free')(p);
    calloc.free(p);
  }

  /// Round 1: fresh random nonce pair + public commitment for a share. Keep the
  /// returned nonces secret; publish the commitment.
  (FrostNonces, FrostCommitment) frostCommit(Uint8List shareSecret, int identifier) {
    final ps = _toNative(shareSecret);
    try {
      final c = _lib.lookupFunction<
          CryptoFrostCommit Function(Pointer<Uint8>, Size, Uint16),
          CryptoFrostCommit Function(Pointer<Uint8>, int, int)>('cryptolib_frost_commit')(
          ps, shareSecret.length, identifier);
      return _frostCommitOut(c, identifier);
    } finally { if (ps != nullptr) calloc.free(ps); }
  }

  /// Deterministic round-1 commit from caller-supplied nonces (test vectors).
  (FrostNonces, FrostCommitment) frostCommitWithNonces(int identifier, Uint8List hiding, Uint8List binding) {
    final ph = _toNative(hiding), pb = _toNative(binding);
    try {
      final c = _lib.lookupFunction<
          CryptoFrostCommit Function(Uint16, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoFrostCommit Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_frost_commit_with_nonces')(
          identifier, ph, hiding.length, pb, binding.length);
      return _frostCommitOut(c, identifier);
    } finally { if (ph != nullptr) calloc.free(ph); if (pb != nullptr) calloc.free(pb); }
  }

  (FrostNonces, FrostCommitment) _frostCommitOut(CryptoFrostCommit c, int identifier) {
    if (c.error != nullptr) {
      final m = c.error.toDartString();
      _frostCommitFree(c);
      throw Exception(m);
    }
    final nonces = FrostNonces(_frostCopy(c.hidingNonce), _frostCopy(c.bindingNonce));
    final commit = FrostCommitment(identifier, _frostCopy(c.hidingCommit), _frostCopy(c.bindingCommit));
    _frostCommitFree(c);
    return (nonces, commit);
  }

  void _frostCommitFree(CryptoFrostCommit c) {
    final p = calloc<CryptoFrostCommit>();
    p.ref.hidingNonce.data = c.hidingNonce.data;     p.ref.hidingNonce.len = c.hidingNonce.len;
    p.ref.bindingNonce.data = c.bindingNonce.data;   p.ref.bindingNonce.len = c.bindingNonce.len;
    p.ref.hidingCommit.data = c.hidingCommit.data;   p.ref.hidingCommit.len = c.hidingCommit.len;
    p.ref.bindingCommit.data = c.bindingCommit.data; p.ref.bindingCommit.len = c.bindingCommit.len;
    p.ref.error = c.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoFrostCommit>),
        void Function(Pointer<CryptoFrostCommit>)>('cryptolib_frost_commit_free')(p);
    calloc.free(p);
  }

  // Flatten commitments into the three parallel wire arrays (caller frees them).
  (Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>) _frostBufs(List<FrostCommitment> cs) {
    final n = cs.length;
    final ids = calloc<Uint16>(n == 0 ? 1 : n);
    final hid = calloc<Uint8>(n == 0 ? 1 : n * 32);
    final bnd = calloc<Uint8>(n == 0 ? 1 : n * 32);
    if (n > 0) {
      final hidList = hid.asTypedList(n * 32);
      final bndList = bnd.asTypedList(n * 32);
      for (var i = 0; i < n; i++) {
        ids[i] = cs[i].identifier;
        hidList.setAll(i * 32, cs[i].hiding);
        bndList.setAll(i * 32, cs[i].binding);
      }
    }
    return (ids, hid, bnd);
  }

  /// Round 2: this participant's 32-byte signature share. [commitments] is the
  /// full round-1 set from every participating signer (including self).
  Uint8List frostSign(int identifier, Uint8List shareSecret, Uint8List groupPublicKey,
      FrostNonces nonces, Uint8List msg, List<FrostCommitment> commitments) {
    final ps = _toNative(shareSecret), pg = _toNative(groupPublicKey);
    final ph = _toNative(nonces.hiding), pbn = _toNative(nonces.binding), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Uint16, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, int)>('cryptolib_frost_sign')(
          identifier, ps, shareSecret.length, pg, groupPublicKey.length,
          ph, nonces.hiding.length, pbn, nonces.binding.length, pm, msg.length,
          ids, hid, bnd, commitments.length));
    } finally {
      for (final p in [ps, pg, ph, pbn, pm]) { if (p != nullptr) calloc.free(p); }
      calloc.free(ids); calloc.free(hid); calloc.free(bnd);
    }
  }

  /// Aggregate signature shares into one 64-byte Ed25519 signature.
  Uint8List frostAggregate(Uint8List groupPublicKey, Uint8List msg,
      List<FrostCommitment> commitments, List<Uint8List> sigShares) {
    final pg = _toNative(groupPublicKey), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    final flat = Uint8List(sigShares.length * 32);
    for (var i = 0; i < sigShares.length; i++) { flat.setAll(i * 32, sigShares[i]); }
    final pf = _toNative(flat);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>)>('cryptolib_frost_aggregate')(
          pg, groupPublicKey.length, pm, msg.length, ids, hid, bnd, commitments.length, pf));
    } finally {
      if (pg != nullptr) calloc.free(pg);
      if (pm != nullptr) calloc.free(pm);
      if (pf != nullptr) calloc.free(pf);
      calloc.free(ids); calloc.free(hid); calloc.free(bnd);
    }
  }

  /// Verify an aggregate signature with standard Ed25519.
  bool frostVerify(Uint8List msg, Uint8List sig, Uint8List groupPublicKey) {
    final pm = _toNative(msg), psig = _toNative(sig), pg = _toNative(groupPublicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_frost_verify')(
          pm, msg.length, psig, sig.length, pg, groupPublicKey.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (psig != nullptr) calloc.free(psig);
      if (pg != nullptr) calloc.free(pg);
    }
  }

  /// Verify one participant's signature share against its public share.
  bool frostVerifyShare(int identifier, Uint8List publicShare, Uint8List sigShare,
      FrostCommitment commitment, Uint8List groupPublicKey, Uint8List msg,
      List<FrostCommitment> commitments) {
    final pp = _toNative(publicShare), pss = _toNative(sigShare);
    final pch = _toNative(commitment.hiding), pcb = _toNative(commitment.binding);
    final pg = _toNative(groupPublicKey), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    try {
      return _lib.lookupFunction<
          Int32 Function(Uint16, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, Size),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, int)>('cryptolib_frost_verify_share')(
          identifier, pp, publicShare.length, pss, sigShare.length,
          pch, commitment.hiding.length, pcb, commitment.binding.length,
          pg, groupPublicKey.length, pm, msg.length, ids, hid, bnd, commitments.length) == 1;
    } finally {
      for (final p in [pp, pss, pch, pcb, pg, pm]) { if (p != nullptr) calloc.free(p); }
      calloc.free(ids); calloc.free(hid); calloc.free(bnd);
    }
  }
}
