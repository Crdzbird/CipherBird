part of '../cryptolib.dart';

// ── HPKE — Hybrid Public Key Encryption (RFC 9180) ────────────────────────────
// The wire-standard hybrid PKE used by TLS ECH, MLS, and Oblivious HTTP. KEM is
// DHKEM(X25519, HKDF-SHA256); an envelope sealed here opens in any conformant
// HPKE implementation.


/// An established one-directional HPKE context. Stateful; close() when done.
class HpkeContext {
  final CryptoLib _cl;
  Pointer<Void> _h;
  HpkeContext(this._cl, this._h);

  /// Sender: AEAD-seal the next message (advances the sequence).
  Uint8List seal(Uint8List plaintext, {Uint8List? aad}) => _cl._hpkeMsg('cryptolib_hpke_seal', _h, plaintext, aad);

  /// Receiver: AEAD-open the next message (advances the sequence).
  Uint8List open(Uint8List ciphertext, {Uint8List? aad}) => _cl._hpkeMsg('cryptolib_hpke_open', _h, ciphertext, aad);

  /// Derive a length-byte secret bound to this context (RFC 9180 §5.3).
  Uint8List export(Uint8List exporterContext, int length) => _cl._hpkeExport(_h, exporterContext, length);

  void close() { if (_h != nullptr) { _cl._hpkeFree(_h); _h = nullptr; } }
}

/// Sender-side HPKE result: the KEM encapsulation plus the sender context.
class HpkeSender {
  final Uint8List enc;
  final HpkeContext context;
  HpkeSender(this.enc, this.context);
}

/// HPKE (RFC 9180) methods on CryptoLib.
extension CryptoLibHpke on CryptoLib {
  /// Fresh X25519 key pair for HPKE.
  KeyPairResult hpkeKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>('cryptolib_hpke_keygen')());

  /// Deterministic DHKEM(X25519).DeriveKeyPair from input keying material.
  KeyPairResult hpkeDeriveKeyPair(Uint8List ikm) {
    final p = _toNative(ikm);
    try {
      return _extractKeyPair(_lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int)>('cryptolib_hpke_derive_keypair')(p, ikm.length));
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Sender key schedule (any mode). Returns the KEM encapsulation + context.
  HpkeSender hpkeSetupS(HpkeKdf kdf, HpkeAead aead, HpkeMode mode, Uint8List recipientPublic, Uint8List info,
      {Uint8List? psk, Uint8List? pskId, Uint8List? senderSecret}) {
    final ppk = _toNative(recipientPublic), pinfo = _toNative(info);
    final ppsk = psk != null ? _toNative(psk) : nullptr;
    final ppid = pskId != null ? _toNative(pskId) : nullptr;
    final psks = senderSecret != null ? _toNative(senderSecret) : nullptr;
    final encOut = calloc<CryptoBuffer>();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Int32, Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<CryptoBuffer>, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, int, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<CryptoBuffer>, Pointer<Pointer<Utf8>>)>('cryptolib_hpke_setup_s')(
          kdf.value, aead.value, mode.value, ppk, recipientPublic.length, pinfo, info.length,
          ppsk, psk?.length ?? 0, ppid, pskId?.length ?? 0, psks, senderSecret?.length ?? 0, encOut, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: hpke setup_s failed');
      final enc = _copyBuf(encOut.ref);
      return HpkeSender(enc, HpkeContext(this, h));
    } finally {
      for (final p in [ppk, pinfo, ppsk, ppid, psks]) { if (p != nullptr) calloc.free(p); }
      calloc.free(encOut); calloc.free(errPtr);
    }
  }

  /// Receiver key schedule (any mode). Returns the established context.
  HpkeContext hpkeSetupR(HpkeKdf kdf, HpkeAead aead, HpkeMode mode, Uint8List enc, Uint8List recipientSecret, Uint8List info,
      {Uint8List? psk, Uint8List? pskId, Uint8List? senderPublic}) {
    final pe = _toNative(enc), psk_ = _toNative(recipientSecret), pinfo = _toNative(info);
    final ppsk = psk != null ? _toNative(psk) : nullptr;
    final ppid = pskId != null ? _toNative(pskId) : nullptr;
    final pks = senderPublic != null ? _toNative(senderPublic) : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Int32, Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, int, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_hpke_setup_r')(
          kdf.value, aead.value, mode.value, pe, enc.length, psk_, recipientSecret.length, pinfo, info.length,
          ppsk, psk?.length ?? 0, ppid, pskId?.length ?? 0, pks, senderPublic?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: hpke setup_r failed');
      return HpkeContext(this, h);
    } finally {
      for (final p in [pe, psk_, pinfo, ppsk, ppid, pks]) { if (p != nullptr) calloc.free(p); }
      calloc.free(errPtr);
    }
  }

  /// Single-shot base-mode encryption → (enc, ciphertext).
  (Uint8List, Uint8List) hpkeSealBase(HpkeKdf kdf, HpkeAead aead, Uint8List recipientPublic, Uint8List info,
      Uint8List plaintext, {Uint8List? aad}) {
    final s = hpkeSetupS(kdf, aead, HpkeMode.base, recipientPublic, info);
    try { return (s.enc, s.context.seal(plaintext, aad: aad)); } finally { s.context.close(); }
  }

  /// Single-shot base-mode decryption.
  Uint8List hpkeOpenBase(HpkeKdf kdf, HpkeAead aead, Uint8List enc, Uint8List recipientSecret, Uint8List info,
      Uint8List ciphertext, {Uint8List? aad}) {
    final r = hpkeSetupR(kdf, aead, HpkeMode.base, enc, recipientSecret, info);
    try { return r.open(ciphertext, aad: aad); } finally { r.close(); }
  }

  Uint8List _hpkeMsg(String symbol, Pointer<Void> h, Uint8List data, Uint8List? aad) {
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pd = _toNative(data);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          h, pa, aad?.length ?? 0, pd, data.length));
    } finally { if (pa != nullptr) calloc.free(pa); if (pd != nullptr) calloc.free(pd); }
  }

  Uint8List _hpkeExport(Pointer<Void> h, Uint8List exporterContext, int length) {
    final pc = exporterContext.isNotEmpty ? _toNative(exporterContext) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, int)>('cryptolib_hpke_export')(
          h, pc, exporterContext.length, length));
    } finally { if (pc != nullptr) calloc.free(pc); }
  }

  void _hpkeFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_hpke_context_free')(h);
}
