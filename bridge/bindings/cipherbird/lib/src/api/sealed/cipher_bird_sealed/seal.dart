part of '../../../cipher_bird.dart';

/// Sealed-messaging methods on CipherBird (tier 0=Flagship, 1=Fortress).
extension CipherBirdSealedSeal on CipherBird {
  Uint8List sealedSeal(
    SealedTier tier,
    Uint8List pt,
    Uint8List recipientPublic,
    Uint8List senderSecret, {
    Uint8List? aad,
    Uint8List? purpose,
  }) {
    final pp = _toNative(pt),
        pr = _toNative(recipientPublic),
        ps = _toNative(senderSecret);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pu = (purpose != null && purpose.isNotEmpty)
        ? _toNative(purpose)
        : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Int32,
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
          ),
          CipherBirdBufferResult Function(
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
          )
        >('cryptolib_sealed_seal')(
          tier.value,
          pp,
          pt.length,
          pr,
          recipientPublic.length,
          ps,
          senderSecret.length,
          pa,
          aad?.length ?? 0,
          pu,
          purpose?.length ?? 0,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (pr != nullptr) {
        calloc.free(pr);
      }
      if (ps != nullptr) {
        calloc.free(ps);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
      if (pu != nullptr) {
        calloc.free(pu);
      }
    }
  }
}
