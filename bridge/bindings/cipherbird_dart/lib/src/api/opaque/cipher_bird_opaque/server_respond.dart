part of '../../../cipher_bird.dart';

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CipherBird.
extension CipherBirdOpaqueServerRespond on CipherBird {
  /// Server login step 1: -> {ke2, serverState}.
  OpaqueKe2 opaqueServerRespond(
    Uint8List context,
    Uint8List serverPrivateKey,
    Uint8List serverPublicKey,
    Uint8List record,
    Uint8List credentialIdentifier,
    Uint8List oprfSeed,
    Uint8List ke1, {
    Uint8List? serverIdentity,
    Uint8List? clientIdentity,
  }) {
    final ptrs = [
      context,
      serverPrivateKey,
      serverPublicKey,
      record,
      credentialIdentifier,
      oprfSeed,
      ke1,
    ].map(_toNative).toList();
    final si = serverIdentity != null ? _toNative(serverIdentity) : nullptr;
    final ci = clientIdentity != null ? _toNative(clientIdentity) : nullptr;
    try {
      final r =
          _lib.lookupFunction<_OpaqueServerRespondC, _OpaqueServerRespondDart>(
            'cryptolib_opaque_server_respond',
          )(
            ptrs[0],
            context.length,
            ptrs[1],
            serverPrivateKey.length,
            ptrs[2],
            serverPublicKey.length,
            ptrs[3],
            record.length,
            ptrs[4],
            credentialIdentifier.length,
            ptrs[5],
            oprfSeed.length,
            ptrs[6],
            ke1.length,
            si,
            serverIdentity?.length ?? 0,
            ci,
            clientIdentity?.length ?? 0,
          );
      if (r.error != nullptr) {
        final m = r.error.toDartString();
        _opaqueKe2Free(r);
        throw Exception(m);
      }
      final out = OpaqueKe2(_frostCopy(r.ke2), _frostCopy(r.serverState));
      _opaqueKe2Free(r);
      return out;
    } finally {
      for (final x in [...ptrs, si, ci]) {
        if (x != nullptr) calloc.free(x);
      }
    }
  }
}
