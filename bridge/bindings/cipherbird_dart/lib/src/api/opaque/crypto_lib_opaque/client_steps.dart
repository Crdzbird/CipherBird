part of '../../../cipher_bird.dart';

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CipherBird.
extension CipherBirdOpaqueClientSteps on CipherBird {
  /// Client registration step 2: -> {record, exportKey}.
  OpaqueRecord opaqueFinalizeRequest(
    Uint8List password,
    Uint8List blind,
    Uint8List response, {
    Uint8List? serverIdentity,
    Uint8List? clientIdentity,
  }) {
    final a = _toNative(password),
        b = _toNative(blind),
        c = _toNative(response);
    final si = serverIdentity != null ? _toNative(serverIdentity) : nullptr;
    final ci = clientIdentity != null ? _toNative(clientIdentity) : nullptr;
    try {
      final r =
          _lib.lookupFunction<
            CryptoOpaqueRecord Function(
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
            CryptoOpaqueRecord Function(
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
          >('cryptolib_opaque_finalize_request')(
            a,
            password.length,
            b,
            blind.length,
            c,
            response.length,
            si,
            serverIdentity?.length ?? 0,
            ci,
            clientIdentity?.length ?? 0,
          );
      if (r.error != nullptr) {
        final m = r.error.toDartString();
        _opaqueRecordFree(r);
        throw Exception(m);
      }
      final out = OpaqueRecord(_frostCopy(r.record), _frostCopy(r.exportKey));
      _opaqueRecordFree(r);
      return out;
    } finally {
      for (final x in [a, b, c, si, ci]) {
        if (x != nullptr) calloc.free(x);
      }
    }
  }

  /// Client login step 1: -> {ke1, clientState}.
  OpaqueKe1 opaqueClientInit(Uint8List password) {
    final p = _toNative(password);
    try {
      final r = _lib
          .lookupFunction<
            CryptoOpaqueKe1 Function(Pointer<Uint8>, Size),
            CryptoOpaqueKe1 Function(Pointer<Uint8>, int)
          >('cryptolib_opaque_client_init')(p, password.length);
      if (r.error != nullptr) {
        final m = r.error.toDartString();
        _opaqueKe1Free(r);
        throw Exception(m);
      }
      final out = OpaqueKe1(_frostCopy(r.ke1), _frostCopy(r.clientState));
      _opaqueKe1Free(r);
      return out;
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }
}
