part of '../cipher_bird.dart';

/// BBS anonymous credentials: selective disclosure, pseudonyms, blind issuance.
extension type BbsApi(CipherBird _l) {
  /// KeyGen from key material (>= 32 B) + optional key info. Throws on failure.
  KeyPairResult keygen(Uint8List keyMaterial, {Uint8List? keyInfo}) =>
      _l.bbsKeygen(keyMaterial, keyInfo: keyInfo);

  /// Derive the 96-byte public key from a 32-byte secret key.
  Uint8List skToPk(Uint8List secretKey) => _l.bbsSkToPk(secretKey);

  /// Sign a vector of messages -> 80-byte signature.
  Uint8List sign(
    Uint8List secretKey,
    Uint8List publicKey,
    Uint8List header,
    List<Uint8List> messages,
  ) => _l.bbsSign(secretKey, publicKey, header, messages);

  /// Verify a signature over a vector of messages.
  bool verify(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    List<Uint8List> messages,
  ) => _l.bbsVerify(publicKey, signature, header, messages);

  /// Derive a selective-disclosure proof. `messages` is the FULL signed vector;
  /// `disclosedIndexes` (0-based) selects which to reveal.
  Uint8List proofGen(
    Uint8List publicKey,
    Uint8List signature,
    Uint8List header,
    Uint8List ph,
    List<Uint8List> messages,
    List<int> disclosedIndexes,
  ) => _l.bbsProofGen(
    publicKey,
    signature,
    header,
    ph,
    messages,
    disclosedIndexes,
  );

  /// Verify a selective-disclosure proof against the revealed messages.
  bool proofVerify(
    Uint8List publicKey,
    Uint8List proof,
    Uint8List header,
    Uint8List ph,
    List<Uint8List> disclosedMessages,
    List<int> disclosedIndexes,
  ) => _l.bbsProofVerify(
    publicKey,
    proof,
    header,
    ph,
    disclosedMessages,
    disclosedIndexes,
  );

  /// Commit to [committedMessages] plus [proverNyms] (secret scalars the issuer
  /// must not learn). Returns (commitmentWithProof, secretProverBlind).
  (Uint8List, Uint8List) commitWithNym(
    List<Uint8List> committedMessages,
    List<Uint8List> proverNyms,
  ) => _l.bbsCommitWithNym(committedMessages, proverNyms);

  /// Blind-sign over the commitment + signer [messages], folding
  /// [signerNymEntropy] into the last nym slot. Returns an 80-byte signature.
  Uint8List blindSignWithNym(
    Uint8List secretKey,
    Uint8List publicKey,
    Uint8List commitmentWithProof,
    Uint8List header,
    List<Uint8List> messages,
    Uint8List signerNymEntropy,
    int lengthNymVector,
  ) => _l.bbsBlindSignWithNym(
    secretKey,
    publicKey,
    commitmentWithProof,
    header,
    messages,
    signerNymEntropy,
    lengthNymVector,
  );

  /// Finalize nym_secrets = [proverNyms] with the last element +=
  /// [signerNymEntropy]. Returns concatenated 32-byte scalars.
  Uint8List finalizeNymSecrets(
    List<Uint8List> proverNyms,
    Uint8List signerNymEntropy,
  ) => _l.bbsFinalizeNymSecrets(proverNyms, signerNymEntropy);
}
