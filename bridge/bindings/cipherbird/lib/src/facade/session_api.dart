part of '../cryptolib.dart';

/// Forward-secret ratcheting sessions.
extension type SessionApi(CryptoLib _l) {
  /// Responder: generate a prekey (hybrid-KEM keypair). Publish publicKey.
  KeyPairResult generateSessionPrekey() => _l.generateSessionPrekey();

  /// Initiator: start a session to the responder's prekey public key.
  Session initiateSession(Uint8List responderPrekeyPublic) =>
      _l.initiateSession(responderPrekeyPublic);

  /// Responder: accept a handshake with your prekey (public + secret).
  Session acceptSession(
    Uint8List handshake,
    Uint8List prekeyPublic,
    Uint8List prekeySecret,
  ) => _l.acceptSession(handshake, prekeyPublic, prekeySecret);
}
