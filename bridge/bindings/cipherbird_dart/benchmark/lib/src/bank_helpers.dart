import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';

/// One HPKE base-mode seal and open over X-Wing.
void hpkeRoundTrip(CipherBird lib, KeyPairResult bob, Uint8List kib) {
  final s = lib.hpkeSetupSKem(
    HpkeKem.xWing,
    HpkeKdf.sha256,
    HpkeAead.aes256Gcm,
    HpkeMode.base,
    bob.publicKey,
    kib,
  );
  final ct = s.context.seal(kib);
  s.context.close();
  final r = lib.hpkeSetupRKem(
    HpkeKem.xWing,
    HpkeKdf.sha256,
    HpkeAead.aes256Gcm,
    HpkeMode.base,
    s.enc,
    bob.secretKey,
    kib,
  );
  r.open(ct);
  r.close();
}

/// A complete Session v2 handshake; the caller closes both channels.
(Session2, Session2) sessionHandshake(
  CipherBird lib,
  KeyPairResult responder,
  KeyPairResult initiator,
) {
  final prekey = lib.generateSession2Prekey(responder.secretKey);
  final a = lib.initiateSession2(
    prekey.publicKey,
    responder.publicKey,
    initiator.publicKey,
    initiator.secretKey,
  );
  final hs = a.handshake();
  final b = lib.acceptSession2(
    hs,
    prekey.publicKey,
    prekey.secretKey,
    responder.publicKey,
    responder.secretKey,
    initiator.publicKey,
  );
  return (a, b);
}
