part of '../../cryptolib.dart';

/// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
extension BbsApiPseudonyms on BbsApi {
  /// Derive the deterministic pseudonym (48-byte compressed G1 point) for a
  /// context from the [nymSecrets].
  Uint8List calculatePseudonym(
    Uint8List contextId,
    List<Uint8List> nymSecrets,
  ) => _l.bbsCalculatePseudonym(contextId, nymSecrets);

  /// Generate a pseudonym-bound selective-disclosure proof. Returns
  /// (proof, pseudonym). Disclosed index lists are 0-based into the signer and
  /// committed message vectors respectively.
  (Uint8List, Uint8List) proofGenWithPseudonym(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    Uint8List ph,
    Uint8List contextId,
    List<Uint8List> signerMessages,
    List<Uint8List> committedMessages,
    Uint8List secretProverBlind,
    List<Uint8List> nymSecrets,
    List<int> disclosedSignerIndexes,
    List<int> disclosedCommittedIndexes,
  ) => _l.bbsProofGenWithPseudonym(
    publicKey,
    signature,
    header,
    ph,
    contextId,
    signerMessages,
    committedMessages,
    secretProverBlind,
    nymSecrets,
    disclosedSignerIndexes,
    disclosedCommittedIndexes,
  );

  /// Verify a pseudonym-bound proof. [disclosedMessages]/[disclosedIndexes] are
  /// the COMBINED signer+committed disclosures (committed index j passed as j+L+1).
  bool proofVerifyWithPseudonym(
    Uint8List publicKey,
    Uint8List proof,
    Uint8List header,
    Uint8List ph,
    Uint8List contextId,
    Uint8List pseudonym,
    int L,
    int lengthNymVector,
    List<Uint8List> disclosedMessages,
    List<int> disclosedIndexes,
  ) => _l.bbsProofVerifyWithPseudonym(
    publicKey,
    proof,
    header,
    ph,
    contextId,
    pseudonym,
    L,
    lengthNymVector,
    disclosedMessages,
    disclosedIndexes,
  );

  /// Commit to [committedMessages] (which the signer never learns). Returns
  /// (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) blindCommit(List<Uint8List> committedMessages) =>
      _l.bbsBlindCommit(committedMessages);

  /// Blind-sign over the commitment + signer [messages] -> 80-byte signature.
  Uint8List blindSign(
    Uint8List secretKey,
    Uint8List publicKey,
    Uint8List commitmentWithProof,
    Uint8List header,
    List<Uint8List> messages,
  ) => _l.bbsBlindSign(
    secretKey,
    publicKey,
    commitmentWithProof,
    header,
    messages,
  );
}
