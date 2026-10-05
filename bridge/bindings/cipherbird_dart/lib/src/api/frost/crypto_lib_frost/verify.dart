part of '../../../cipher_bird.dart';

/// FROST threshold-signature methods on CipherBird.
extension CipherBirdFrostVerify on CipherBird {
  /// Verify an aggregate signature with standard Ed25519.
  bool frostVerify(Uint8List msg, Uint8List sig, Uint8List groupPublicKey) {
    final pm = _toNative(msg),
        psig = _toNative(sig),
        pg = _toNative(groupPublicKey);
    try {
      return _lib.lookupFunction<
            Int32 Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            int Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >('cryptolib_frost_verify')(
            pm,
            msg.length,
            psig,
            sig.length,
            pg,
            groupPublicKey.length,
          ) ==
          1;
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (psig != nullptr) {
        calloc.free(psig);
      }
      if (pg != nullptr) {
        calloc.free(pg);
      }
    }
  }
}
