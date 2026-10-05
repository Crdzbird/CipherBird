part of '../cryptolib.dart';

/// FROST t-of-n threshold signatures.
extension type FrostApi(CryptoLib _l) {
  /// Trusted-dealer split: any [t] of [n] shares can sign. Share i (0-based) has
  /// FROST identifier i+1. Output verifies with standard Ed25519 verification.
  FrostKeyGen keygen(int n, int t) => _l.frostKeygen(n, t);

  /// Round 1: fresh random nonce pair + public commitment for a share. Keep the
  /// returned nonces secret; publish the commitment.
  (FrostNonces, FrostCommitment) commit(
    Uint8List shareSecret,
    int identifier,
  ) => _l.frostCommit(shareSecret, identifier);

  /// Deterministic round-1 commit from caller-supplied nonces (test vectors).
  (FrostNonces, FrostCommitment) commitWithNonces(
    int identifier,
    Uint8List hiding,
    Uint8List binding,
  ) => _l.frostCommitWithNonces(identifier, hiding, binding);

  /// Round 2: this participant's 32-byte signature share. [commitments] is the
  /// full round-1 set from every participating signer (including self).
  Uint8List sign(
    int identifier,
    Uint8List shareSecret,
    Uint8List groupPublicKey,
    FrostNonces nonces,
    Uint8List msg,
    List<FrostCommitment> commitments,
  ) => _l.frostSign(
    identifier,
    shareSecret,
    groupPublicKey,
    nonces,
    msg,
    commitments,
  );

  /// Aggregate signature shares into one 64-byte Ed25519 signature.
  Uint8List aggregate(
    Uint8List groupPublicKey,
    Uint8List msg,
    List<FrostCommitment> commitments,
    List<Uint8List> sigShares,
  ) => _l.frostAggregate(groupPublicKey, msg, commitments, sigShares);

  /// Verify an aggregate signature with standard Ed25519.
  bool verify(Uint8List msg, Uint8List sig, Uint8List groupPublicKey) =>
      _l.frostVerify(msg, sig, groupPublicKey);

  /// Verify one participant's signature share against its public share.
  bool verifyShare(
    int identifier,
    Uint8List publicShare,
    Uint8List sigShare,
    FrostCommitment commitment,
    Uint8List groupPublicKey,
    Uint8List msg,
    List<FrostCommitment> commitments,
  ) => _l.frostVerifyShare(
    identifier,
    publicShare,
    sigShare,
    commitment,
    groupPublicKey,
    msg,
    commitments,
  );
}
