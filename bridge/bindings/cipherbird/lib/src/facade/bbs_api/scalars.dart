part of '../../cipher_bird.dart';

/// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
extension BbsApiScalars on BbsApi {
  /// Verify a blind signature over [messages] + [committedMessages] using the
  /// [secretProverBlind] kept from [blindCommit].
  bool verifyBlindSign(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    List<Uint8List> messages,
    List<Uint8List> committedMessages,
    Uint8List secretProverBlind,
  ) => _l.bbsVerifyBlindSign(
    publicKey,
    signature,
    header,
    messages,
    committedMessages,
    secretProverBlind,
  );

  /// Deterministically map (msg, dst) to a canonical scalar in [0, r) - the BBS
  /// hash_to_scalar primitive. Use for a stable per-holder nym seed:
  /// nymSeed = bbsHashToScalar(memberSecret, dst).
  Uint8List hashToScalar(Uint8List msg, Uint8List dst) =>
      _l.bbsHashToScalar(msg, dst);

  /// A fresh cryptographically-random canonical scalar in [0, r) (32 bytes BE).
  Uint8List randomScalar() => _l.bbsRandomScalar();
}
