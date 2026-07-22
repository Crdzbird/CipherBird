part of '../cryptolib.dart';

// ── Session — PQ forward-secret ratchet (hybrid KEM Double Ratchet) ───────────
// A live channel with forward secrecy + post-compromise security, all
// post-quantum. Where Flagship/Fortress seal to a static recipient key, a Session
// self-heals after a one-time state leak, once each side ratchets again.

/// A post-quantum forward-secret ratchet channel. Stateful — not safe for
/// concurrent use; close() when done.
class Session {
  final CryptoLib _cl;
  Pointer<Void> _h;
  Session(this._cl, this._h);

  /// The handshake message to send to the responder (acceptSession). Empty on a responder.
  Uint8List handshake() => _cl._sessionHandshake(_h);

  /// Encrypt the next outgoing message (advances the sending ratchet).
  Uint8List encrypt(Uint8List plaintext, {Uint8List? aad}) =>
      _cl._sessionMsg('cryptolib_session_encrypt', _h, plaintext, aad);

  /// Decrypt an incoming message (handles ratchet turns + out-of-order; transactional).
  Uint8List decrypt(Uint8List message, {Uint8List? aad}) =>
      _cl._sessionMsg('cryptolib_session_decrypt', _h, message, aad);

  void close() { if (_h != nullptr) { _cl._sessionFree(_h); _h = nullptr; } }
}

/// Session (ratchet) methods on CryptoLib.
extension CryptoLibSession on CryptoLib {
  /// Responder: generate a prekey (hybrid-KEM keypair). Publish publicKey.
  KeyPairResult generateSessionPrekey() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_session_generate_prekey')());

  /// Initiator: start a session to the responder's prekey public key.
  Session initiateSession(Uint8List responderPrekeyPublic) {
    final pp = _toNative(responderPrekeyPublic);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_session_initiate')(
          pp, responderPrekeyPublic.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: session initiate failed');
      return Session(this, h);
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  /// Responder: accept a handshake with your prekey (public + secret).
  Session acceptSession(Uint8List handshake, Uint8List prekeyPublic, Uint8List prekeySecret) {
    final ph = _toNative(handshake), pub = _toNative(prekeyPublic), sec = _toNative(prekeySecret);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_session_accept')(
          ph, handshake.length, pub, prekeyPublic.length, sec, prekeySecret.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: session accept failed');
      return Session(this, h);
    } finally {
      if (ph != nullptr) calloc.free(ph);
      if (pub != nullptr) calloc.free(pub);
      if (sec != nullptr) calloc.free(sec);
      calloc.free(errPtr);
    }
  }

  Uint8List _sessionHandshake(Pointer<Void> h) => _checkBufResult(_lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>), CryptoBufferResult Function(Pointer<Void>)>('cryptolib_session_handshake')(h));

  Uint8List _sessionMsg(String symbol, Pointer<Void> h, Uint8List data, Uint8List? aad) {
    final pd = _toNative(data);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          h, pd, data.length, pa, aad?.length ?? 0));
    } finally { if (pd != nullptr) calloc.free(pd); if (pa != nullptr) calloc.free(pa); }
  }

  void _sessionFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_session_free')(h);
}
