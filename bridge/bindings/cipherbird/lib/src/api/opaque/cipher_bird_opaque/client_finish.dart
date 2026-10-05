part of '../../../cipher_bird.dart';

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CipherBird.
extension CipherBirdOpaqueClientFinish on CipherBird {
  /// Client login step 2: authenticate server -> {ke3, sessionKey, exportKey}.
  /// Throws on a wrong password / server authentication failure.
  OpaqueKe3 opaqueClientFinish(
    Uint8List clientState,
    Uint8List ke2,
    Uint8List context, {
    Uint8List? serverIdentity,
    Uint8List? clientIdentity,
  }) {
    final a = _toNative(clientState),
        b = _toNative(ke2),
        c = _toNative(context);
    final si = serverIdentity != null ? _toNative(serverIdentity) : nullptr;
    final ci = clientIdentity != null ? _toNative(clientIdentity) : nullptr;
    try {
      final r =
          _lib.lookupFunction<
            CipherBirdOpaqueKe3 Function(
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
            CipherBirdOpaqueKe3 Function(
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
          >('cryptolib_opaque_client_finish')(
            a,
            clientState.length,
            b,
            ke2.length,
            c,
            context.length,
            si,
            serverIdentity?.length ?? 0,
            ci,
            clientIdentity?.length ?? 0,
          );
      if (r.error != nullptr) {
        final m = r.error.toDartString();
        _opaqueKe3Free(r);
        throw Exception(m);
      }
      final out = OpaqueKe3(
        _frostCopy(r.ke3),
        _frostCopy(r.sessionKey),
        _frostCopy(r.exportKey),
      );
      _opaqueKe3Free(r);
      return out;
    } finally {
      for (final x in [a, b, c, si, ci]) {
        if (x != nullptr) calloc.free(x);
      }
    }
  }
}
