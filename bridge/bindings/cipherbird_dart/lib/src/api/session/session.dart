part of '../../cipher_bird.dart';

/// A post-quantum forward-secret ratchet channel. Stateful - not safe for
/// concurrent use; close() when done.
final class Session {
  final CipherBird _cl;
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

  void close() {
    if (_h != nullptr) {
      _cl._sessionFree(_h);
      _h = nullptr;
    }
  }
}
