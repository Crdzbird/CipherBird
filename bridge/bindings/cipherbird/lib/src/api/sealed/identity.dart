part of '../../cryptolib.dart';

/// A party's keypairs - recipient (KEM) for receiving, sender (signature) for
/// signing. The config/setup handle for the sealed-messaging API.
final class Identity {
  final CryptoLib lib;
  final SealedTier tier;
  final Uint8List recipientPublic, recipientSecret, senderPublic, senderSecret;
  Identity(
    this.lib,
    this.tier,
    this.recipientPublic,
    this.recipientSecret,
    this.senderPublic,
    this.senderSecret,
  );

  Uint8List seal(
    Uint8List plaintext,
    Uint8List recipientPublic, {
    Uint8List? aad,
    Uint8List? purpose,
  }) => lib.sealedSeal(
    tier,
    plaintext,
    recipientPublic,
    senderSecret,
    aad: aad,
    purpose: purpose,
  );
  Uint8List open(
    Uint8List envelope,
    Uint8List senderPublic, {
    Uint8List? aad,
    Uint8List? purpose,
  }) => lib.sealedOpen(
    tier,
    envelope,
    recipientSecret,
    recipientPublic,
    senderPublic,
    aad: aad,
    purpose: purpose,
  );
  SealedStreamSealer newStreamSealer(
    Uint8List recipientPublic, {
    Uint8List? purpose,
  }) => lib.sealedSealerBegin(
    tier,
    recipientPublic,
    senderSecret,
    purpose: purpose,
  );
  SealedStreamOpener newStreamOpener(
    Uint8List preamble,
    Uint8List senderPublic, {
    Uint8List? purpose,
  }) => lib.sealedOpenerBegin(
    tier,
    preamble,
    recipientSecret,
    recipientPublic,
    senderPublic,
    purpose: purpose,
  );
}
