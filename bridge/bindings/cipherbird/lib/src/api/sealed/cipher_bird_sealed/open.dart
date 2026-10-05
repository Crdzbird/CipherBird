part of '../../../cipher_bird.dart';

/// Sealed-messaging methods on CipherBird (tier 0=Flagship, 1=Fortress).
extension CipherBirdSealedOpen on CipherBird {
  Uint8List sealedOpen(
    SealedTier tier,
    Uint8List envelope,
    Uint8List recipientSecret,
    Uint8List recipientPublic,
    Uint8List senderPublic, {
    Uint8List? aad,
    Uint8List? purpose,
  }) {
    final pe = _toNative(envelope),
        prs = _toNative(recipientSecret),
        prp = _toNative(recipientPublic),
        psp = _toNative(senderPublic);
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
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_sealed_open')(
          tier.value,
          pe,
          envelope.length,
          prs,
          recipientSecret.length,
          prp,
          recipientPublic.length,
          psp,
          senderPublic.length,
          pa,
          aad?.length ?? 0,
          pu,
          purpose?.length ?? 0,
        ),
      );
    } finally {
      if (pe != nullptr) {
        calloc.free(pe);
      }
      if (prs != nullptr) {
        calloc.free(prs);
      }
      if (prp != nullptr) {
        calloc.free(prp);
      }
      if (psp != nullptr) {
        calloc.free(psp);
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
