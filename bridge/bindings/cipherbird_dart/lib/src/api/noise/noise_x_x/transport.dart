part of '../../../cryptolib.dart';

/// Noise_XX_25519_ChaChaPoly_SHA256 - mutual static-key authentication and
/// forward secrecy.
///
/// Handshake: initiator [writeMessage], responder [readMessage]+[writeMessage],
/// initiator [readMessage]+[writeMessage], responder [readMessage]; then both
/// [split]. Not thread-safe ([decryptAt] is re-entrant, see there). Call [close].
extension NoiseXXTransport on NoiseXX {
  /// Derive the transport states (Noise Split). Throws if the handshake is
  /// unfinished or split already ran.
  void split() {
    final ok = _lib._lib
        .lookupFunction<
          Int32 Function(Pointer<Void>),
          int Function(Pointer<Void>)
        >('cryptolib_noise_split')(_h);
    if (ok != 1) {
      throw Exception(
        'cryptolib: noise split failed (handshake unfinished or already split)',
      );
    }
  }

  /// Seal one transport record (after [split]).
  Uint8List encrypt(Uint8List plaintext, [Uint8List? ad]) =>
      _withBuf('cryptolib_noise_encrypt', plaintext, ad);

  /// Open the next record in sequence (after [split]).
  Uint8List decrypt(Uint8List ciphertext, [Uint8List? ad]) =>
      _withBuf('cryptolib_noise_decrypt', ciphertext, ad);

  /// Open the record sent at [nonceCounter] WITHOUT advancing the session
  /// counter, so several records can be opened at once.
  ///
  /// Caller's duty: use each sender counter (from 0 per direction) at most
  /// once and reassemble in order - statelessly a replay is indistinguishable
  /// from a fresh record. Do not mix with [encrypt]/[decrypt] concurrently.
  /// There is deliberately no explicit-nonce encrypt: nonce reuse leaks the key.
  Uint8List decryptAt(int nonceCounter, Uint8List ciphertext, [Uint8List? ad]) {
    final pc = _lib._toNative(ciphertext);
    final pa = (ad == null || ad.isEmpty) ? nullptr : _lib._toNative(ad);
    try {
      return _lib._checkBufResult(
        _lib._lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Uint64,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Void>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_noise_decrypt_at')(
          _h,
          nonceCounter,
          pc,
          ciphertext.length,
          pa,
          ad?.length ?? 0,
        ),
      );
    } finally {
      if (pc != nullptr) {
        calloc.free(pc);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
    }
  }

  /// Release the native handle. Idempotent.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_noise_free')(_h);
      _h = nullptr;
    }
  }
}
