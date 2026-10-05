part of '../../cryptolib.dart';

/// Noise_XX_25519_ChaChaPoly_SHA256 - mutual static-key authentication and
/// forward secrecy.
///
/// Handshake: initiator [writeMessage], responder [readMessage]+[writeMessage],
/// initiator [readMessage]+[writeMessage], responder [readMessage]; then both
/// [split]. Not thread-safe ([decryptAt] is re-entrant, see there). Call [close].
final class NoiseXX {
  NoiseXX._(this._lib, this._h);

  final CryptoLib _lib;

  Pointer<Void> _h;

  Uint8List _withBuf(String sym, Uint8List a, [Uint8List? b]) {
    final pa = _lib._toNative(a);
    final pb = (b == null || b.isEmpty) ? nullptr : _lib._toNative(b);
    try {
      return _lib._checkBufResult(
        _lib._lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Void>,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >(sym)(_h, pa, a.length, pb, b?.length ?? 0),
      );
    } finally {
      if (pa != nullptr) {
        calloc.free(pa);
      }
      if (pb != nullptr) {
        calloc.free(pb);
      }
    }
  }

  Uint8List _handshakeMsg(String sym, Uint8List? data) {
    final p = (data == null || data.isEmpty) ? nullptr : _lib._toNative(data);
    try {
      return _lib._checkBufResult(
        _lib._lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >(sym)(_h, p, data?.length ?? 0),
      );
    } finally {
      if (p != nullptr) {
        calloc.free(p);
      }
    }
  }

  /// Next handshake message on this side's turn, embedding an optional payload.
  Uint8List writeMessage([Uint8List? payload]) =>
      _handshakeMsg('cryptolib_noise_write_message', payload);

  /// Consume the peer's handshake message; returns its embedded payload.
  Uint8List readMessage(Uint8List message) =>
      _handshakeMsg('cryptolib_noise_read_message', message);

  /// True once all three handshake messages are processed.
  bool get handshakeFinished =>
      _lib._lib.lookupFunction<
        Int32 Function(Pointer<Void>),
        int Function(Pointer<Void>)
      >('cryptolib_noise_handshake_finished')(_h) ==
      1;

  /// 32-byte channel-binding value both sides agree on after the handshake.
  Uint8List get handshakeHash => _lib._checkBufResult(
    _lib._lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>),
      CryptoBufferResult Function(Pointer<Void>)
    >('cryptolib_noise_handshake_hash')(_h),
  );

  /// The peer's static X25519 public key learned in the handshake - pin it to
  /// stop an active MITM.
  Uint8List get remoteStatic => _lib._checkBufResult(
    _lib._lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>),
      CryptoBufferResult Function(Pointer<Void>)
    >('cryptolib_noise_remote_static')(_h),
  );
}
