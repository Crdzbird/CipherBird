part of '../../../cryptolib.dart';

/// FROST threshold-signature methods on CryptoLib.
extension CryptoLibFrostVerifyShare on CryptoLib {
  /// Verify one participant's signature share against its public share.
  bool frostVerifyShare(
    int identifier,
    Uint8List publicShare,
    Uint8List sigShare,
    FrostCommitment commitment,
    Uint8List groupPublicKey,
    Uint8List msg,
    List<FrostCommitment> commitments,
  ) {
    final pp = _toNative(publicShare), pss = _toNative(sigShare);
    final pch = _toNative(commitment.hiding),
        pcb = _toNative(commitment.binding);
    final pg = _toNative(groupPublicKey), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    try {
      return _lib.lookupFunction<
            Int32 Function(
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
              Pointer<Uint8>,
              Size,
              Pointer<Uint16>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
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
              Pointer<Uint8>,
              int,
              Pointer<Uint16>,
              Pointer<Uint8>,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_frost_verify_share')(
            identifier,
            pp,
            publicShare.length,
            pss,
            sigShare.length,
            pch,
            commitment.hiding.length,
            pcb,
            commitment.binding.length,
            pg,
            groupPublicKey.length,
            pm,
            msg.length,
            ids,
            hid,
            bnd,
            commitments.length,
          ) ==
          1;
    } finally {
      for (final p in [pp, pss, pch, pcb, pg, pm]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(ids);
      calloc.free(hid);
      calloc.free(bnd);
    }
  }
}
