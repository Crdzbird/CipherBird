part of '../../cipher_bird.dart';

/// A Session v2 channel: the X-Wing forward-secret ratchet behind an
/// authenticated handshake. Stateful; not safe for concurrent use; close()
/// when done.
final class Session2 {
  final CipherBird _cl;
  Pointer<Void> _h;
  Session2(this._cl, this._h);

  /// The handshake message to send to the responder (acceptSession2). Empty
  /// on a responder.
  Uint8List handshake() => _cl._session2Handshake(_h);

  /// Encrypt the next outgoing message.
  Uint8List encrypt(Uint8List plaintext, {Uint8List? aad}) =>
      _cl._session2Msg('cryptolib_session2_encrypt', _h, plaintext, aad);

  /// Decrypt an incoming message (ratchet turns and out-of-order handled).
  Uint8List decrypt(Uint8List message, {Uint8List? aad}) =>
      _cl._session2Msg('cryptolib_session2_decrypt', _h, message, aad);

  void close() {
    if (_h != nullptr) {
      _cl._session2Free(_h);
      _h = nullptr;
    }
  }
}
