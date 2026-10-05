part of '../../../cipher_bird.dart';

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CipherBird.
extension CipherBirdOpaqueServerFinish on CipherBird {
  /// Server login step 2: verify KE3 -> the session key (throws on failure).
  Uint8List opaqueServerFinish(Uint8List serverState, Uint8List ke3) {
    final a = _toNative(serverState), b = _toNative(ke3);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
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

  void _opaqueRecordFree(CipherBirdOpaqueRecord r) {
    final p = calloc<CipherBirdOpaqueRecord>();
    p.ref.record.data = r.record.data;
    p.ref.record.len = r.record.len;
    p.ref.exportKey.data = r.exportKey.data;
    p.ref.exportKey.len = r.exportKey.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CipherBirdOpaqueRecord>),
      void Function(Pointer<CipherBirdOpaqueRecord>)
    >('cryptolib_opaque_record_free')(p);
    calloc.free(p);
  }

  void _opaqueKe1Free(CipherBirdOpaqueKe1 r) {
    final p = calloc<CipherBirdOpaqueKe1>();
    p.ref.ke1.data = r.ke1.data;
    p.ref.ke1.len = r.ke1.len;
    p.ref.clientState.data = r.clientState.data;
    p.ref.clientState.len = r.clientState.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CipherBirdOpaqueKe1>),
      void Function(Pointer<CipherBirdOpaqueKe1>)
    >('cryptolib_opaque_ke1_free')(p);
    calloc.free(p);
  }

  void _opaqueKe2Free(CipherBirdOpaqueKe2 r) {
    final p = calloc<CipherBirdOpaqueKe2>();
    p.ref.ke2.data = r.ke2.data;
    p.ref.ke2.len = r.ke2.len;
    p.ref.serverState.data = r.serverState.data;
    p.ref.serverState.len = r.serverState.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CipherBirdOpaqueKe2>),
      void Function(Pointer<CipherBirdOpaqueKe2>)
    >('cryptolib_opaque_ke2_free')(p);
    calloc.free(p);
  }

  void _opaqueKe3Free(CipherBirdOpaqueKe3 r) {
    final p = calloc<CipherBirdOpaqueKe3>();
    p.ref.ke3.data = r.ke3.data;
    p.ref.ke3.len = r.ke3.len;
    p.ref.sessionKey.data = r.sessionKey.data;
    p.ref.sessionKey.len = r.sessionKey.len;
    p.ref.exportKey.data = r.exportKey.data;
    p.ref.exportKey.len = r.exportKey.len;
    p.ref.error = r.error;
    _lib.lookupFunction<
      Void Function(Pointer<CipherBirdOpaqueKe3>),
      void Function(Pointer<CipherBirdOpaqueKe3>)
    >('cryptolib_opaque_ke3_free')(p);
    calloc.free(p);
  }
}
