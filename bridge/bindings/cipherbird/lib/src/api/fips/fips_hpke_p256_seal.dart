part of '../../cipher_bird.dart';

/// FIPS profile HPKE sealing on CipherBird.
extension CipherBirdFipsHpkeP256Seal on CipherBird {
  /// One-shot HPKE base mode to [recipientPublic]. Returns (enc, ciphertext).
  (Uint8List, Uint8List) fipsHpkeP256Seal(
    Uint8List recipientPublic,
    Uint8List plaintext, {
    Uint8List? info,
    Uint8List? aad,
  }) {
    final pk = _toNative(recipientPublic), pt = _toNative(plaintext);
    final pi = info == null ? nullptr : _toNative(info);
    final pa = aad == null ? nullptr : _toNative(aad);
    final encOut = calloc<CipherBirdBuffer>();
    try {
      final ct = _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<CipherBirdBuffer>,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<CipherBirdBuffer>,
          )
        >('cryptolib_fips_hpke_p256_seal')(
          pk,
          recipientPublic.length,
          pi,
          info?.length ?? 0,
          pa,
          aad?.length ?? 0,
          pt,
          plaintext.length,
          encOut,
        ),
      );
      return (_copyBuf(encOut.ref), ct);
    } finally {
      for (final p in [pk, pt, pi, pa]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(encOut);
    }
  }
}
