part of '../../../cryptolib.dart';

/// Sealed-messaging methods on CryptoLib (tier 0=Flagship, 1=Fortress).
extension CryptoLibSealedOpener on CryptoLib {
  SealedStreamOpener sealedOpenerBegin(
    SealedTier tier,
    Uint8List preamble,
    Uint8List recipientSecret,
    Uint8List recipientPublic,
    Uint8List senderPublic, {
    Uint8List? purpose,
  }) {
    final pp = _toNative(preamble),
        prs = _toNative(recipientSecret),
        prp = _toNative(recipientPublic),
        psp = _toNative(senderPublic);
    final pu = (purpose != null && purpose.isNotEmpty)
        ? _toNative(purpose)
        : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
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
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
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
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_sealed_opener_begin')(
            tier.value,
            pp,
            preamble.length,
            prs,
            recipientSecret.length,
            prp,
            recipientPublic.length,
            psp,
            senderPublic.length,
            pu,
            purpose?.length ?? 0,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cryptolib: stream opener begin failed');
      }
      return SealedStreamOpener(this, h);
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
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
      if (pu != nullptr) {
        calloc.free(pu);
      }
      calloc.free(errPtr);
    }
  }
}
