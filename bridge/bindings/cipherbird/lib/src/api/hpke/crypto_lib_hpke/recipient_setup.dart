part of '../../../cryptolib.dart';

/// HPKE (RFC 9180) methods on CryptoLib.
extension CryptoLibHpkeRecipientSetup on CryptoLib {
  /// Receiver key schedule (any mode). Returns the established context.
  HpkeContext hpkeSetupR(
    HpkeKdf kdf,
    HpkeAead aead,
    HpkeMode mode,
    Uint8List enc,
    Uint8List recipientSecret,
    Uint8List info, {
    Uint8List? psk,
    Uint8List? pskId,
    Uint8List? senderPublic,
  }) {
    final pe = _toNative(enc),
        psk_ = _toNative(recipientSecret),
        pinfo = _toNative(info);
    final ppsk = psk != null ? _toNative(psk) : nullptr;
    final ppid = pskId != null ? _toNative(pskId) : nullptr;
    final pks = senderPublic != null ? _toNative(senderPublic) : nullptr;
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
              Pointer<Uint8>,
              Size,
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
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_hpke_setup_r')(
            kdf.value,
            aead.value,
            mode.value,
            pe,
            enc.length,
            psk_,
            recipientSecret.length,
            pinfo,
            info.length,
            ppsk,
            psk?.length ?? 0,
            ppid,
            pskId?.length ?? 0,
            pks,
            senderPublic?.length ?? 0,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final m = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(m);
      }
      if (h == nullptr) {
        throw Exception('cryptolib: hpke setup_r failed');
      }
      return HpkeContext(this, h);
    } finally {
      for (final p in [pe, psk_, pinfo, ppsk, ppid, pks]) {
        if (p != nullptr) calloc.free(p);
      }
      calloc.free(errPtr);
    }
  }
}
