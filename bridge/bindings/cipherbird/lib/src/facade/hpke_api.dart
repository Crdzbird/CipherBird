part of '../cipher_bird.dart';

/// HPKE (RFC 9180) hybrid public-key encryption.
extension type HpkeApi(CipherBird _l) {
  /// Fresh X25519 key pair for HPKE.
  KeyPairResult keygen() => _l.hpkeKeygen();

  /// Deterministic DHKEM(X25519).DeriveKeyPair from input keying material.
  KeyPairResult deriveKeyPair(Uint8List ikm) => _l.hpkeDeriveKeyPair(ikm);

  /// Sender key schedule (any mode). Returns the KEM encapsulation + context.
  HpkeSender setupS(
    HpkeKdf kdf,
    HpkeAead aead,
    HpkeMode mode,
    Uint8List recipientPublic,
    Uint8List info, {
    Uint8List? psk,
    Uint8List? pskId,
    Uint8List? senderSecret,
  }) => _l.hpkeSetupS(
    kdf,
    aead,
    mode,
    recipientPublic,
    info,
    psk: psk,
    pskId: pskId,
    senderSecret: senderSecret,
  );

  /// Receiver key schedule (any mode). Returns the established context.
  HpkeContext setupR(
    HpkeKdf kdf,
    HpkeAead aead,
    HpkeMode mode,
    Uint8List enc,
    Uint8List recipientSecret,
    Uint8List info, {
    Uint8List? psk,
    Uint8List? pskId,
    Uint8List? senderPublic,
  }) => _l.hpkeSetupR(
    kdf,
    aead,
    mode,
    enc,
    recipientSecret,
    info,
    psk: psk,
    pskId: pskId,
    senderPublic: senderPublic,
  );

  /// Single-shot base-mode encryption -> (enc, ciphertext).
  (Uint8List, Uint8List) sealBase(
    HpkeKdf kdf,
    HpkeAead aead,
    Uint8List recipientPublic,
    Uint8List info,
    Uint8List plaintext, {
    Uint8List? aad,
  }) => _l.hpkeSealBase(kdf, aead, recipientPublic, info, plaintext, aad: aad);

  /// Single-shot base-mode decryption.
  Uint8List openBase(
    HpkeKdf kdf,
    HpkeAead aead,
    Uint8List enc,
    Uint8List recipientSecret,
    Uint8List info,
    Uint8List ciphertext, {
    Uint8List? aad,
  }) => _l.hpkeOpenBase(
    kdf,
    aead,
    enc,
    recipientSecret,
    info,
    ciphertext,
    aad: aad,
  );
}
