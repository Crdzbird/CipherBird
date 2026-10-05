part of '../../../cryptolib.dart';

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CryptoLib.
extension CryptoLibOpaqueServerFinish on CryptoLib {
  /// Server login step 2: verify KE3 -> the session key (throws on failure).
  Uint8List opaqueServerFinish(Uint8List serverState, Uint8List ke3) {
    final a = _toNative(serverState), b = _toNative(ke3);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_opaque_server_finish')(
          a,
          serverState.length,
          b,
          ke3.length,
        ),
      );
    } finally {
      if (a != nullptr) calloc.free(a);
      if (b != nullptr) calloc.free(b);
    }
  }

  void _opaqueRecordFree(CryptoOpaqueRecord r) {
    final p = calloc<CryptoOpaqueRecord>();
    p.ref.record.data = r.record.data;
    p.ref.record.len = r.record.len;
    p.ref.exportKey.data = r.exportKey.data;
    p.ref.exportKey.len = r.exportKey.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CryptoOpaqueRecord>),
      void Function(Pointer<CryptoOpaqueRecord>)
    >('cryptolib_opaque_record_free')(p);
    calloc.free(p);
  }

  void _opaqueKe1Free(CryptoOpaqueKe1 r) {
    final p = calloc<CryptoOpaqueKe1>();
    p.ref.ke1.data = r.ke1.data;
    p.ref.ke1.len = r.ke1.len;
    p.ref.clientState.data = r.clientState.data;
    p.ref.clientState.len = r.clientState.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CryptoOpaqueKe1>),
      void Function(Pointer<CryptoOpaqueKe1>)
    >('cryptolib_opaque_ke1_free')(p);
    calloc.free(p);
  }

  void _opaqueKe2Free(CryptoOpaqueKe2 r) {
    final p = calloc<CryptoOpaqueKe2>();
    p.ref.ke2.data = r.ke2.data;
    p.ref.ke2.len = r.ke2.len;
    p.ref.serverState.data = r.serverState.data;
    p.ref.serverState.len = r.serverState.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CryptoOpaqueKe2>),
      void Function(Pointer<CryptoOpaqueKe2>)
    >('cryptolib_opaque_ke2_free')(p);
    calloc.free(p);
  }

  void _opaqueKe3Free(CryptoOpaqueKe3 r) {
    final p = calloc<CryptoOpaqueKe3>();
    p.ref.ke3.data = r.ke3.data;
    p.ref.ke3.len = r.ke3.len;
    p.ref.sessionKey.data = r.sessionKey.data;
    p.ref.sessionKey.len = r.sessionKey.len;
    p.ref.exportKey.data = r.exportKey.data;
    p.ref.exportKey.len = r.exportKey.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CryptoOpaqueKe3>),
      void Function(Pointer<CryptoOpaqueKe3>)
    >('cryptolib_opaque_ke3_free')(p);
    calloc.free(p);
  }
}
