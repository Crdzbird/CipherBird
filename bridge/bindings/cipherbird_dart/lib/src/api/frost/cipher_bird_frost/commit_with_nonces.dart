part of '../../../cipher_bird.dart';

/// FROST threshold-signature methods on CipherBird.
extension CipherBirdFrostCommitWithNonces on CipherBird {
  /// Deterministic round-1 commit from caller-supplied nonces (test vectors).
  (FrostNonces, FrostCommitment) frostCommitWithNonces(
    int identifier,
    Uint8List hiding,
    Uint8List binding,
  ) {
    final ph = _toNative(hiding), pb = _toNative(binding);
    try {
      final c = _lib
          .lookupFunction<
            CipherBirdFrostCommit Function(
              Uint16,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            CipherBirdFrostCommit Function(
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >(
            'cryptolib_frost_commit_with_nonces',
          )(identifier, ph, hiding.length, pb, binding.length);
      return _frostCommitOut(c, identifier);
    } finally {
      if (ph != nullptr) calloc.free(ph);
      if (pb != nullptr) calloc.free(pb);
    }
  }

  (FrostNonces, FrostCommitment) _frostCommitOut(
    CipherBirdFrostCommit c,
    int identifier,
  ) {
    if (c.error != nullptr) {
      final m = c.error.toDartString();
      _frostCommitFree(c);
      throw Exception(m);
    }
    final nonces = FrostNonces(
      _frostCopy(c.hidingNonce),
      _frostCopy(c.bindingNonce),
    );
    final commit = FrostCommitment(
      identifier,
      _frostCopy(c.hidingCommit),
      _frostCopy(c.bindingCommit),
    );
    _frostCommitFree(c);
    return (nonces, commit);
  }

  void _frostCommitFree(CipherBirdFrostCommit c) {
    final p = calloc<CipherBirdFrostCommit>();
    p.ref.hidingNonce.data = c.hidingNonce.data;
    p.ref.hidingNonce.len = c.hidingNonce.len;
    p.ref.bindingNonce.data = c.bindingNonce.data;
    p.ref.bindingNonce.len = c.bindingNonce.len;
    p.ref.hidingCommit.data = c.hidingCommit.data;
    p.ref.hidingCommit.len = c.hidingCommit.len;
    p.ref.bindingCommit.data = c.bindingCommit.data;
    p.ref.bindingCommit.len = c.bindingCommit.len;
    p.ref.error = c.error;
    _lib.lookupFunction<
      Void Function(Pointer<CipherBirdFrostCommit>),
      void Function(Pointer<CipherBirdFrostCommit>)
    >('cryptolib_frost_commit_free')(p);
    calloc.free(p);
  }

  (Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>) _frostBufs(
    List<FrostCommitment> cs,
  ) {
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
}
