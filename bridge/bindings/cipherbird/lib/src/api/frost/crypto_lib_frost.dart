part of '../../cryptolib.dart';

/// FROST threshold-signature methods on CryptoLib.
extension CryptoLibFrost on CryptoLib {
  /// Trusted-dealer split: any [t] of [n] shares can sign. Share i (0-based) has
  /// FROST identifier i+1. Output verifies with standard Ed25519 verification.
  FrostKeyGen frostKeygen(int n, int t) {
    final kg = _lib
        .lookupFunction<
          CryptoFrostKeyGen Function(Uint16, Uint16),
          CryptoFrostKeyGen Function(int, int)
        >('cryptolib_frost_keygen')(n, t);
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
    _lib.lookupFunction<
      Void Function(Pointer<CryptoFrostKeyGen>),
      void Function(Pointer<CryptoFrostKeyGen>)
    >('cryptolib_frost_keygen_free')(p);
    calloc.free(p);
  }

  /// Round 1: fresh random nonce pair + public commitment for a share. Keep the
  /// returned nonces secret; publish the commitment.
  (FrostNonces, FrostCommitment) frostCommit(
    Uint8List shareSecret,
    int identifier,
  ) {
    final ps = _toNative(shareSecret);
    try {
      final c = _lib
          .lookupFunction<
            CryptoFrostCommit Function(Pointer<Uint8>, Size, Uint16),
            CryptoFrostCommit Function(Pointer<Uint8>, int, int)
          >('cryptolib_frost_commit')(ps, shareSecret.length, identifier);
      return _frostCommitOut(c, identifier);
    } finally {
      if (ps != nullptr) calloc.free(ps);
    }
  }
}
