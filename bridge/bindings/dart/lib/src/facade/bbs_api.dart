part of '../../cryptolib_ffi.dart';

/// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
extension type BbsApi(CryptoLib _l) {
  /// KeyGen from key material (>= 32 B) + optional key info. Throws on failure.
  KeyPairResult keygen(Uint8List keyMaterial, {Uint8List? keyInfo}) =>
      _l.bbsKeygen(keyMaterial, keyInfo: keyInfo);

  /// Derive the 96-byte public key from a 32-byte secret key.
  Uint8List skToPk(Uint8List secretKey) => _l.bbsSkToPk(secretKey);

  /// Sign a vector of messages -> 80-byte signature.
  Uint8List sign(Uint8List secretKey, Uint8List publicKey, Uint8List header,
          List<Uint8List> messages) =>
      _l.bbsSign(secretKey, publicKey, header, messages);

  /// Verify a signature over a vector of messages.
  bool verify(Uint8List publicKey, Uint8List signature, Uint8List header,
          List<Uint8List> messages) =>
      _l.bbsVerify(publicKey, signature, header, messages);

  /// Derive a selective-disclosure proof. `messages` is the FULL signed vector;
  /// `disclosedIndexes` (0-based) selects which to reveal.
  Uint8List proofGen(Uint8List publicKey, Uint8List signature, Uint8List header,
          Uint8List ph, List<Uint8List> messages, List<int> disclosedIndexes) =>
      _l.bbsProofGen(
          publicKey, signature, header, ph, messages, disclosedIndexes);

  /// Verify a selective-disclosure proof against the revealed messages.
  bool proofVerify(
          Uint8List publicKey,
          Uint8List proof,
          Uint8List header,
          Uint8List ph,
          List<Uint8List> disclosedMessages,
          List<int> disclosedIndexes) =>
      _l.bbsProofVerify(
          publicKey, proof, header, ph, disclosedMessages, disclosedIndexes);

  /// Commit to [committedMessages] plus [proverNyms] (secret scalars the issuer
  /// must not learn). Returns (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) commitWithNym(
          List<Uint8List> committedMessages, List<Uint8List> proverNyms) =>
      _l.bbsCommitWithNym(committedMessages, proverNyms);

  /// Blind-sign over the commitment + signer [messages], folding
  /// [signerNymEntropy] into the last nym slot. Returns an 80-byte signature.
  Uint8List blindSignWithNym(
          Uint8List secretKey,
          Uint8List publicKey,
          Uint8List commitmentWithProof,
          Uint8List header,
          List<Uint8List> messages,
          Uint8List signerNymEntropy,
          int lengthNymVector) =>
      _l.bbsBlindSignWithNym(secretKey, publicKey, commitmentWithProof, header,
          messages, signerNymEntropy, lengthNymVector);

  /// Finalize nym_secrets = [proverNyms] with the last element +=
  /// [signerNymEntropy]. Returns concatenated 32-byte scalars.
  Uint8List finalizeNymSecrets(
          List<Uint8List> proverNyms, Uint8List signerNymEntropy) =>
      _l.bbsFinalizeNymSecrets(proverNyms, signerNymEntropy);

  /// Derive the deterministic pseudonym (48-byte compressed G1 point) for a
  /// context from the [nymSecrets].
  Uint8List calculatePseudonym(
          Uint8List contextId, List<Uint8List> nymSecrets) =>
      _l.bbsCalculatePseudonym(contextId, nymSecrets);

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
          List<int> disclosedCommittedIndexes) =>
      _l.bbsProofGenWithPseudonym(
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
          disclosedCommittedIndexes);

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
          List<int> disclosedIndexes) =>
      _l.bbsProofVerifyWithPseudonym(publicKey, proof, header, ph, contextId,
          pseudonym, L, lengthNymVector, disclosedMessages, disclosedIndexes);

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
          List<Uint8List> messages) =>
      _l.bbsBlindSign(
          secretKey, publicKey, commitmentWithProof, header, messages);

  /// Verify a blind signature over [messages] + [committedMessages] using the
  /// [secretProverBlind] kept from [bbsBlindCommit].
  bool verifyBlindSign(
          Uint8List publicKey,
          Uint8List signature,
          Uint8List header,
          List<Uint8List> messages,
          List<Uint8List> committedMessages,
          Uint8List secretProverBlind) =>
      _l.bbsVerifyBlindSign(publicKey, signature, header, messages,
          committedMessages, secretProverBlind);

  /// Deterministically map (msg, dst) to a canonical scalar in [0, r) - the BBS
  /// hash_to_scalar primitive. Use for a stable per-holder nym seed:
  /// nymSeed = bbsHashToScalar(memberSecret, dst).
  Uint8List hashToScalar(Uint8List msg, Uint8List dst) =>
      _l.bbsHashToScalar(msg, dst);

  /// A fresh cryptographically-random canonical scalar in [0, r) (32 bytes BE).
  Uint8List randomScalar() => _l.bbsRandomScalar();
}
