part of '../cipher_bird.dart';

/// BLS12-381 signing, verification and aggregation.
extension type BlsApi(CipherBird _l) {
  KeyPairResult keygen() => _l.blsKeygen();

  Uint8List sign(Uint8List msg, Uint8List secretKey) =>
      _l.blsSign(msg, secretKey);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey) =>
      _l.blsVerify(msg, sig, publicKey);

  /// Deterministic BLS keygen from input key material. [ikm] must be >= 32
  /// bytes (per IRTF draft-irtf-cfrg-bls-signature KeyGen). Same IKM -> same key.
  KeyPairResult keygenFromIkm(Uint8List ikm) => _l.blsKeygenFromIkm(ikm);

  /// Aggregate N BLS signatures (each a 96-byte compressed G2 point) into a
  /// single 96-byte signature. Throws if [sigs] is empty.
  Uint8List aggregate(List<Uint8List> sigs) => _l.blsAggregate(sigs);

  /// Verify an aggregate signature over N (message, public key) pairs in a
  /// single operation. [messages] and [publicKeys] must be the same length and
  /// positionally correspond. Returns true iff every signature is valid.
  bool aggregateVerify(
    List<Uint8List> messages,
    List<Uint8List> publicKeys,
    Uint8List aggSig,
  ) => _l.blsAggregateVerify(messages, publicKeys, aggSig);
}
