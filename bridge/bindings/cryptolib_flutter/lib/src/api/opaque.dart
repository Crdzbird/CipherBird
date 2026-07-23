part of '../cryptolib.dart';

// ── OPAQUE — asymmetric PAKE (OPAQUE-3DH, ristretto255-SHA-512) ───────────────
// Client and server agree on a session key from a password that never leaves the
// client and is never stored server-side. Registration, then a 3DH login.

/// OPAQUE registration record (store server-side) + export key.
class OpaqueRecord {
  final Uint8List record;
  final Uint8List exportKey;
  OpaqueRecord(this.record, this.exportKey);
}

/// OPAQUE client login message 1 + opaque client state.
class OpaqueKe1 {
  final Uint8List ke1;
  final Uint8List clientState;
  OpaqueKe1(this.ke1, this.clientState);
}

/// OPAQUE server login message 2 + opaque server state.
class OpaqueKe2 {
  final Uint8List ke2;
  final Uint8List serverState;
  OpaqueKe2(this.ke2, this.serverState);
}

/// OPAQUE client login message 3 + the session key + export key.
class OpaqueKe3 {
  final Uint8List ke3;
  final Uint8List sessionKey;
  final Uint8List exportKey;
  OpaqueKe3(this.ke3, this.sessionKey, this.exportKey);
}

/// OPAQUE (draft-irtf-cfrg-opaque, OPAQUE-3DH) methods on CryptoLib.
extension CryptoLibOpaque on CryptoLib {
  /// Client registration step 1: blind the password → {blind, request}.
  OprfBlindResult opaqueRegistrationRequest(Uint8List password) {
    final p = _toNative(password);
    try {
      final c = _lib.lookupFunction<
          CryptoOprfBlind Function(Pointer<Uint8>, Size),
          CryptoOprfBlind Function(Pointer<Uint8>, int)>('cryptolib_opaque_registration_request')(p, password.length);
      return _oprfBlindOut(c);
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Server registration step: → 64-byte registration response.
  Uint8List opaqueRegistrationResponse(Uint8List request, Uint8List serverPublicKey,
      Uint8List credentialIdentifier, Uint8List oprfSeed) {
    final a = _toNative(request), b = _toNative(serverPublicKey), c = _toNative(credentialIdentifier), d = _toNative(oprfSeed);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_opaque_registration_response')(
          a, request.length, b, serverPublicKey.length, c, credentialIdentifier.length, d, oprfSeed.length));
    } finally { for (final x in [a, b, c, d]) { if (x != nullptr) calloc.free(x); } }
  }

  /// Client registration step 2: → {record, exportKey}.
  OpaqueRecord opaqueFinalizeRequest(Uint8List password, Uint8List blind, Uint8List response,
      {Uint8List? serverIdentity, Uint8List? clientIdentity}) {
    final a = _toNative(password), b = _toNative(blind), c = _toNative(response);
    final si = serverIdentity != null ? _toNative(serverIdentity) : nullptr;
    final ci = clientIdentity != null ? _toNative(clientIdentity) : nullptr;
    try {
      final r = _lib.lookupFunction<
          CryptoOpaqueRecord Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoOpaqueRecord Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_opaque_finalize_request')(
          a, password.length, b, blind.length, c, response.length, si, serverIdentity?.length ?? 0, ci, clientIdentity?.length ?? 0);
      if (r.error != nullptr) { final m = r.error.toDartString(); _opaqueRecordFree(r); throw Exception(m); }
      final out = OpaqueRecord(_frostCopy(r.record), _frostCopy(r.exportKey));
      _opaqueRecordFree(r);
      return out;
    } finally { for (final x in [a, b, c, si, ci]) { if (x != nullptr) calloc.free(x); } }
  }

  /// Client login step 1: → {ke1, clientState}.
  OpaqueKe1 opaqueClientInit(Uint8List password) {
    final p = _toNative(password);
    try {
      final r = _lib.lookupFunction<
          CryptoOpaqueKe1 Function(Pointer<Uint8>, Size),
          CryptoOpaqueKe1 Function(Pointer<Uint8>, int)>('cryptolib_opaque_client_init')(p, password.length);
      if (r.error != nullptr) { final m = r.error.toDartString(); _opaqueKe1Free(r); throw Exception(m); }
      final out = OpaqueKe1(_frostCopy(r.ke1), _frostCopy(r.clientState));
      _opaqueKe1Free(r);
      return out;
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Server login step 1: → {ke2, serverState}.
  OpaqueKe2 opaqueServerRespond(Uint8List context, Uint8List serverPrivateKey, Uint8List serverPublicKey,
      Uint8List record, Uint8List credentialIdentifier, Uint8List oprfSeed, Uint8List ke1,
      {Uint8List? serverIdentity, Uint8List? clientIdentity}) {
    final ptrs = [context, serverPrivateKey, serverPublicKey, record, credentialIdentifier, oprfSeed, ke1]
        .map(_toNative).toList();
    final si = serverIdentity != null ? _toNative(serverIdentity) : nullptr;
    final ci = clientIdentity != null ? _toNative(clientIdentity) : nullptr;
    try {
      final r = _lib.lookupFunction<
          CryptoOpaqueKe2 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoOpaqueKe2 Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_opaque_server_respond')(
          ptrs[0], context.length, ptrs[1], serverPrivateKey.length, ptrs[2], serverPublicKey.length,
          ptrs[3], record.length, ptrs[4], credentialIdentifier.length, ptrs[5], oprfSeed.length, ptrs[6], ke1.length,
          si, serverIdentity?.length ?? 0, ci, clientIdentity?.length ?? 0);
      if (r.error != nullptr) { final m = r.error.toDartString(); _opaqueKe2Free(r); throw Exception(m); }
      final out = OpaqueKe2(_frostCopy(r.ke2), _frostCopy(r.serverState));
      _opaqueKe2Free(r);
      return out;
    } finally { for (final x in [...ptrs, si, ci]) { if (x != nullptr) calloc.free(x); } }
  }

  /// Client login step 2: authenticate server → {ke3, sessionKey, exportKey}.
  /// Throws on a wrong password / server authentication failure.
  OpaqueKe3 opaqueClientFinish(Uint8List clientState, Uint8List ke2, Uint8List context,
      {Uint8List? serverIdentity, Uint8List? clientIdentity}) {
    final a = _toNative(clientState), b = _toNative(ke2), c = _toNative(context);
    final si = serverIdentity != null ? _toNative(serverIdentity) : nullptr;
    final ci = clientIdentity != null ? _toNative(clientIdentity) : nullptr;
    try {
      final r = _lib.lookupFunction<
          CryptoOpaqueKe3 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoOpaqueKe3 Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_opaque_client_finish')(
          a, clientState.length, b, ke2.length, c, context.length, si, serverIdentity?.length ?? 0, ci, clientIdentity?.length ?? 0);
      if (r.error != nullptr) { final m = r.error.toDartString(); _opaqueKe3Free(r); throw Exception(m); }
      final out = OpaqueKe3(_frostCopy(r.ke3), _frostCopy(r.sessionKey), _frostCopy(r.exportKey));
      _opaqueKe3Free(r);
      return out;
    } finally { for (final x in [a, b, c, si, ci]) { if (x != nullptr) calloc.free(x); } }
  }

  /// Server login step 2: verify KE3 → the session key (throws on failure).
  Uint8List opaqueServerFinish(Uint8List serverState, Uint8List ke3) {
    final a = _toNative(serverState), b = _toNative(ke3);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_opaque_server_finish')(
          a, serverState.length, b, ke3.length));
    } finally { if (a != nullptr) calloc.free(a); if (b != nullptr) calloc.free(b); }
  }

  void _opaqueRecordFree(CryptoOpaqueRecord r) {
    final p = calloc<CryptoOpaqueRecord>();
    p.ref.record.data = r.record.data; p.ref.record.len = r.record.len;
    p.ref.exportKey.data = r.exportKey.data; p.ref.exportKey.len = r.exportKey.len;
    p.ref.error = r.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoOpaqueRecord>), void Function(Pointer<CryptoOpaqueRecord>)>('cryptolib_opaque_record_free')(p);
    calloc.free(p);
  }
  void _opaqueKe1Free(CryptoOpaqueKe1 r) {
    final p = calloc<CryptoOpaqueKe1>();
    p.ref.ke1.data = r.ke1.data; p.ref.ke1.len = r.ke1.len;
    p.ref.clientState.data = r.clientState.data; p.ref.clientState.len = r.clientState.len;
    p.ref.error = r.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoOpaqueKe1>), void Function(Pointer<CryptoOpaqueKe1>)>('cryptolib_opaque_ke1_free')(p);
    calloc.free(p);
  }
  void _opaqueKe2Free(CryptoOpaqueKe2 r) {
    final p = calloc<CryptoOpaqueKe2>();
    p.ref.ke2.data = r.ke2.data; p.ref.ke2.len = r.ke2.len;
    p.ref.serverState.data = r.serverState.data; p.ref.serverState.len = r.serverState.len;
    p.ref.error = r.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoOpaqueKe2>), void Function(Pointer<CryptoOpaqueKe2>)>('cryptolib_opaque_ke2_free')(p);
    calloc.free(p);
  }
  void _opaqueKe3Free(CryptoOpaqueKe3 r) {
    final p = calloc<CryptoOpaqueKe3>();
    p.ref.ke3.data = r.ke3.data; p.ref.ke3.len = r.ke3.len;
    p.ref.sessionKey.data = r.sessionKey.data; p.ref.sessionKey.len = r.sessionKey.len;
    p.ref.exportKey.data = r.exportKey.data; p.ref.exportKey.len = r.exportKey.len;
    p.ref.error = r.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoOpaqueKe3>), void Function(Pointer<CryptoOpaqueKe3>)>('cryptolib_opaque_ke3_free')(p);
    calloc.free(p);
  }
}
