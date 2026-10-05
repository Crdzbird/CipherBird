part of '../../cryptolib_ffi.dart';

/// Flagship / Fortress sealed messaging.
extension type SealedApi(CryptoLib _l) {
  /// Generate a party's recipient (KEM) + sender (signature) keypairs.
  Identity identity(SealedTier tier) => _l.newIdentity(tier);

  /// Read an envelope's public header without any key. Null if unrecognizable.
  SealedInfo? inspect(Uint8List envelope) => _l.sealedInspect(envelope);

  /// Whether the envelope is addressed to recipientPublic (fingerprint match).
  bool addressedTo(Uint8List envelope, Uint8List recipientPublic) =>
      _l.sealedAddressedTo(envelope, recipientPublic);

  Uint8List seal(SealedTier tier, Uint8List pt, Uint8List recipientPublic,
          Uint8List senderSecret, {Uint8List? aad, Uint8List? purpose}) =>
      _l.sealedSeal(tier, pt, recipientPublic, senderSecret,
          aad: aad, purpose: purpose);

  Uint8List open(SealedTier tier, Uint8List envelope, Uint8List recipientSecret,
          Uint8List recipientPublic, Uint8List senderPublic,
          {Uint8List? aad, Uint8List? purpose}) =>
      _l.sealedOpen(
          tier, envelope, recipientSecret, recipientPublic, senderPublic,
          aad: aad, purpose: purpose);

  SealedStreamSealer sealerBegin(
          SealedTier tier, Uint8List recipientPublic, Uint8List senderSecret,
          {Uint8List? purpose}) =>
      _l.sealedSealerBegin(tier, recipientPublic, senderSecret,
          purpose: purpose);

  SealedStreamOpener openerBegin(
          SealedTier tier,
          Uint8List preamble,
          Uint8List recipientSecret,
          Uint8List recipientPublic,
          Uint8List senderPublic,
          {Uint8List? purpose}) =>
      _l.sealedOpenerBegin(
          tier, preamble, recipientSecret, recipientPublic, senderPublic,
          purpose: purpose);
}
