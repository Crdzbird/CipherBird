part of '../../../cipher_bird.dart';

/// FROST threshold-signature methods on CipherBird.
extension CipherBirdFrostAggregate on CipherBird {
  /// Aggregate signature shares into one 64-byte Ed25519 signature.
  Uint8List frostAggregate(
    Uint8List groupPublicKey,
    Uint8List msg,
    List<FrostCommitment> commitments,
    List<Uint8List> sigShares,
  ) {
    final pg = _toNative(groupPublicKey), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    final flat = Uint8List(sigShares.length * 32);
    for (var i = 0; i < sigShares.length; i++) {
      flat.setAll(i * 32, sigShares[i]);
    }
    final pf = _toNative(flat);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint16>,
            Pointer<Uint8>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint16>,
            Pointer<Uint8>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
          )
        >('cryptolib_frost_aggregate')(
          pg,
          groupPublicKey.length,
          pm,
          msg.length,
          ids,
          hid,
          bnd,
          commitments.length,
          pf,
        ),
      );
    } finally {
      if (pg != nullptr) {
        calloc.free(pg);
      }
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pf != nullptr) {
        calloc.free(pf);
      }
      calloc.free(ids);
      calloc.free(hid);
      calloc.free(bnd);
    }
  }
}
