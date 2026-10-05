part of '../../../cryptolib.dart';

/// HPKE (RFC 9180) methods on CryptoLib.
extension CryptoLibHpkeSenderSetup on CryptoLib {
  /// Sender key schedule (any mode). Returns the KEM encapsulation + context.
  HpkeSender hpkeSetupS(
    HpkeKdf kdf,
    HpkeAead aead,
    HpkeMode mode,
    Uint8List recipientPublic,
    Uint8List info, {
    Uint8List? psk,
    Uint8List? pskId,
    Uint8List? senderSecret,
  }) {
    final ppk = _toNative(recipientPublic), pinfo = _toNative(info);
    final ppsk = psk != null ? _toNative(psk) : nullptr;
    final ppid = pskId != null ? _toNative(pskId) : nullptr;
    final psks = senderSecret != null ? _toNative(senderSecret) : nullptr;
    final encOut = calloc<CryptoBuffer>();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
              Int32,
              Int32,
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
              Pointer<CryptoBuffer>,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
              int,
              int,
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
              Pointer<CryptoBuffer>,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_hpke_setup_s')(
            kdf.value,
            aead.value,
            mode.value,
            ppk,
            recipientPublic.length,
            pinfo,
            info.length,
            ppsk,
            psk?.length ?? 0,
            ppid,
            pskId?.length ?? 0,
            psks,
            senderSecret?.length ?? 0,
            encOut,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cryptolib: hpke setup_s failed');
      }
      final enc = _copyBuf(encOut.ref);
      return HpkeSender(enc, HpkeContext(this, h));
    } finally {
      for (final p in [ppk, pinfo, ppsk, ppid, psks]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(encOut);
      calloc.free(errPtr);
    }
  }
}
