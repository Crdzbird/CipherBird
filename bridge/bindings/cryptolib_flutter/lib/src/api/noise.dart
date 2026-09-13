part of '../cryptolib.dart';

// ── Incremental BLAKE3 + Noise XX secure channel ─────────────────────────────

/// Incremental BLAKE3. The digest equals `blake3()` over the concatenation of
/// every [update]. Not thread-safe; call [close] when done.
class Blake3Hasher {
  Blake3Hasher._(this._lib, this._h);
  final CryptoLib _lib;
  Pointer<Void> _h;

  /// Feed bytes. Throws after [finalize].
  void update(Uint8List data) {
    final p = _lib._toNative(data);
    try {
      final ok = _lib._lib.lookupFunction<
          Int32 Function(Pointer<Void>, Pointer<Uint8>, Size),
          int Function(Pointer<Void>, Pointer<Uint8>, int)>('cryptolib_blake3_hasher_update')(_h, p, data.length);
      if (ok != 1) throw Exception('cryptolib: blake3 update failed (closed or finalized?)');
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Produce the digest; [outLen] 0 means 32 bytes, larger uses extendable
  /// output. The hasher accepts no further updates afterwards.
  Uint8List finalize({int outLen = 0}) => _lib._checkBufResult(_lib._lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>, Size),
      CryptoBufferResult Function(Pointer<Void>, int)>('cryptolib_blake3_hasher_finalize')(_h, outLen));

  /// Release the native handle. Idempotent.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_blake3_hasher_free')(_h);
      _h = nullptr;
    }
  }
}

/// Noise_XX_25519_ChaChaPoly_SHA256 — mutual static-key authentication and
/// forward secrecy.
///
/// Handshake: initiator [writeMessage], responder [readMessage]+[writeMessage],
/// initiator [readMessage]+[writeMessage], responder [readMessage]; then both
/// [split]. Not thread-safe ([decryptAt] is re-entrant, see there). Call [close].
class NoiseXX {
  NoiseXX._(this._lib, this._h);
  final CryptoLib _lib;
  Pointer<Void> _h;

  Uint8List _withBuf(String sym, Uint8List a, [Uint8List? b]) {
    final pa = _lib._toNative(a);
    final pb = (b == null || b.isEmpty) ? nullptr : _lib._toNative(b);
    try {
      return _lib._checkBufResult(_lib._lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(sym)(
          _h, pa, a.length, pb, b?.length ?? 0));
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
    }
  }

  Uint8List _handshakeMsg(String sym, Uint8List? data) {
    final p = (data == null || data.isEmpty) ? nullptr : _lib._toNative(data);
    try {
      return _lib._checkBufResult(_lib._lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>(sym)(_h, p, data?.length ?? 0));
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Next handshake message on this side's turn, embedding an optional payload.
  Uint8List writeMessage([Uint8List? payload]) => _handshakeMsg('cryptolib_noise_write_message', payload);

  /// Consume the peer's handshake message; returns its embedded payload.
  Uint8List readMessage(Uint8List message) => _handshakeMsg('cryptolib_noise_read_message', message);

  /// True once all three handshake messages are processed.
  bool get handshakeFinished => _lib._lib.lookupFunction<
      Int32 Function(Pointer<Void>), int Function(Pointer<Void>)>('cryptolib_noise_handshake_finished')(_h) == 1;

  /// 32-byte channel-binding value both sides agree on after the handshake.
  Uint8List get handshakeHash => _lib._checkBufResult(_lib._lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>), CryptoBufferResult Function(Pointer<Void>)>('cryptolib_noise_handshake_hash')(_h));

  /// The peer's static X25519 public key learned in the handshake — pin it to
  /// stop an active MITM.
  Uint8List get remoteStatic => _lib._checkBufResult(_lib._lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>), CryptoBufferResult Function(Pointer<Void>)>('cryptolib_noise_remote_static')(_h));

  /// Derive the transport states (Noise Split). Throws if the handshake is
  /// unfinished or split already ran.
  void split() {
    final ok = _lib._lib.lookupFunction<Int32 Function(Pointer<Void>), int Function(Pointer<Void>)>('cryptolib_noise_split')(_h);
    if (ok != 1) throw Exception('cryptolib: noise split failed (handshake unfinished or already split)');
  }

  /// Seal one transport record (after [split]).
  Uint8List encrypt(Uint8List plaintext, [Uint8List? ad]) => _withBuf('cryptolib_noise_encrypt', plaintext, ad);

  /// Open the next record in sequence (after [split]).
  Uint8List decrypt(Uint8List ciphertext, [Uint8List? ad]) => _withBuf('cryptolib_noise_decrypt', ciphertext, ad);

  /// Open the record sent at [nonceCounter] WITHOUT advancing the session
  /// counter, so several records can be opened at once.
  ///
  /// Caller's duty: use each sender counter (from 0 per direction) at most
  /// once and reassemble in order — statelessly a replay is indistinguishable
  /// from a fresh record. Do not mix with [encrypt]/[decrypt] concurrently.
  /// There is deliberately no explicit-nonce encrypt: nonce reuse leaks the key.
  Uint8List decryptAt(int nonceCounter, Uint8List ciphertext, [Uint8List? ad]) {
    final pc = _lib._toNative(ciphertext);
    final pa = (ad == null || ad.isEmpty) ? nullptr : _lib._toNative(ad);
    try {
      return _lib._checkBufResult(_lib._lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Uint64, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_noise_decrypt_at')(
          _h, nonceCounter, pc, ciphertext.length, pa, ad?.length ?? 0));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Release the native handle. Idempotent.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_noise_free')(_h);
      _h = nullptr;
    }
  }
}

/// Incremental BLAKE3 and Noise XX constructors on CryptoLib.
extension CryptoLibNoise on CryptoLib {
  /// Incremental BLAKE3; pass a 32-byte [key] for keyed (MAC) mode.
  Blake3Hasher blake3Hasher({Uint8List? key}) {
    if (key != null && key.length != 32) throw ArgumentError('cryptolib: BLAKE3 key must be exactly 32 bytes');
    final p = (key == null) ? nullptr : _toNative(key);
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size),
          Pointer<Void> Function(Pointer<Uint8>, int)>('cryptolib_blake3_hasher_create')(p, key?.length ?? 0);
      if (h == nullptr) throw Exception('cryptolib: blake3 hasher create failed (BLAKE3 not enabled?)');
      return Blake3Hasher._(this, h);
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Create a Noise XX state from this side's X25519 keypair (see
  /// `x25519Keygen`). Both sides must use the same [prologue].
  NoiseXX noise({required bool initiator, required Uint8List staticPublic,
      required Uint8List staticSecret, Uint8List? prologue}) {
    if (staticPublic.length != 32 || staticSecret.length != 32) {
      throw ArgumentError('cryptolib: Noise static keys must be 32 bytes each');
    }
    final pp = _toNative(staticPublic), ps = _toNative(staticSecret);
    final pr = (prologue == null || prologue.isEmpty) ? nullptr : _toNative(prologue);
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          Pointer<Void> Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_noise_create')(
          initiator ? 1 : 0, pp, 32, ps, 32, pr, prologue?.length ?? 0);
      if (h == nullptr) throw Exception('cryptolib: noise create failed');
      return NoiseXX._(this, h);
    } finally {
      calloc.free(pp); calloc.free(ps);
      if (pr != nullptr) calloc.free(pr);
    }
  }
}
