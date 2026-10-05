part of '../../../cipher_bird.dart';

/// FROST threshold-signature methods on CipherBird.
extension CipherBirdFrostSign on CipherBird {
  /// Round 2: this participant's 32-byte signature share. [commitments] is the
  /// full round-1 set from every participating signer (including self).
  Uint8List frostSign(
    int identifier,
    Uint8List shareSecret,
    Uint8List groupPublicKey,
    FrostNonces nonces,
    Uint8List msg,
    List<FrostCommitment> commitments,
  ) {
    final ps = _toNative(shareSecret), pg = _toNative(groupPublicKey);
    final ph = _toNative(nonces.hiding),
        pbn = _toNative(nonces.binding),
        pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Uint16,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint16>,
            Pointer<Uint8>,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint16>,
            Pointer<Uint8>,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_frost_sign')(
          identifier,
          ps,
          shareSecret.length,
          pg,
          groupPublicKey.length,
          ph,
          nonces.hiding.length,
          pbn,
          nonces.binding.length,
          pm,
          msg.length,
          ids,
          hid,
          bnd,
          commitments.length,
        ),
      );
    } finally {
      for (final p in [ps, pg, ph, pbn, pm]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(ids);
      calloc.free(hid);
      calloc.free(bnd);
    }
  }
}
