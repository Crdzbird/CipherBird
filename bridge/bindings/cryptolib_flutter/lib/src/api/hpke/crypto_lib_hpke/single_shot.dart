part of '../../../cryptolib.dart';

/// HPKE (RFC 9180) methods on CryptoLib.
extension CryptoLibHpkeSingleShot on CryptoLib {
  /// Single-shot base-mode encryption -> (enc, ciphertext).
  (Uint8List, Uint8List) hpkeSealBase(
    HpkeKdf kdf,
    HpkeAead aead,
    Uint8List recipientPublic,
    Uint8List info,
    Uint8List plaintext, {
    Uint8List? aad,
  }) {
    final s = hpkeSetupS(kdf, aead, HpkeMode.base, recipientPublic, info);
    try {
      return (s.enc, s.context.seal(plaintext, aad: aad));
    } finally {
      s.context.close();
    }
  }

  /// Single-shot base-mode decryption.
  Uint8List hpkeOpenBase(
    HpkeKdf kdf,
    HpkeAead aead,
    Uint8List enc,
    Uint8List recipientSecret,
    Uint8List info,
    Uint8List ciphertext, {
    Uint8List? aad,
  }) {
    final r = hpkeSetupR(kdf, aead, HpkeMode.base, enc, recipientSecret, info);
    try {
      return r.open(ciphertext, aad: aad);
    } finally {
      r.close();
    }
  }

  Uint8List _hpkeMsg(
    String symbol,
    Pointer<Void> h,
    Uint8List data,
    Uint8List? aad,
  ) {
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pd = _toNative(data);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >(symbol)(h, pa, aad?.length ?? 0, pd, data.length),
      );
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pd != nullptr) calloc.free(pd);
    }
  }

  Uint8List _hpkeExport(
    Pointer<Void> h,
    Uint8List exporterContext,
    int length,
  ) {
    final pc = exporterContext.isNotEmpty
        ? _toNative(exporterContext)
        : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Size,
          ),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, int)
        >('cryptolib_hpke_export')(h, pc, exporterContext.length, length),
      );
    } finally {
      if (pc != nullptr) calloc.free(pc);
    }
  }
}
