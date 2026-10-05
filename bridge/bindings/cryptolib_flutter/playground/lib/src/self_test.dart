import 'package:cryptolib_flutter/cryptolib_flutter.dart';

const _shaAbc =
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

List<(String, bool)> selfTest(CryptoLib lib) {
  final alice = lib.easy.identity(SealedTier.fortress);
  final bob = lib.easy.identity(SealedTier.fortress);
  final envelope = bob.sealText('hello', to: alice.recipientPublic);
  return [
    ('CryptoLib ${lib.version()} loaded', lib.version().isNotEmpty),
    ('SHA-256 known answer', lib.easy.sha256Hex('abc') == _shaAbc),
    (
      'Fortress sealed messaging (sntrup761 inside)',
      alice.openText(envelope, from: bob.senderPublic) == 'hello',
    ),
    ('Noise XX handshake and transport', noiseRoundTrip(lib)),
  ];
}

bool noiseRoundTrip(CryptoLib lib) {
  final initiatorKeys = lib.x25519Keygen();
  final responderKeys = lib.x25519Keygen();
  final initiator = lib.noise(
    initiator: true,
    staticPublic: initiatorKeys.publicKey,
    staticSecret: initiatorKeys.secretKey,
  );
  final responder = lib.noise(
    initiator: false,
    staticPublic: responderKeys.publicKey,
    staticSecret: responderKeys.secretKey,
  );
  responder.readMessage(initiator.writeMessage('hi'.bytes));
  initiator.readMessage(responder.writeMessage());
  responder.readMessage(initiator.writeMessage());
  initiator.split();
  responder.split();
  final ok =
      responder.decrypt(initiator.encrypt('record'.bytes)).text == 'record';
  initiator.close();
  responder.close();
  return ok;
}
