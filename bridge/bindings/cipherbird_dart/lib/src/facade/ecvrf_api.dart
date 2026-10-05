part of '../cryptolib.dart';

/// ECVRF (RFC 9381) verifiable random function.
extension type EcvrfApi(CryptoLib _l) {
  /// ECVRF key pair (pk 32 B, sk = 32-byte seed).
  KeyPairResult keygen() => _l.ecvrfKeygen();

  /// Derive the public key Y = x,B from a 32-byte secret seed.
  Uint8List publicKey(Uint8List secretKey) => _l.ecvrfPublicKey(secretKey);

  /// Prove: returns the 80-byte proof for (sk, alpha).
  Uint8List prove(Uint8List secretKey, Uint8List alpha) =>
      _l.ecvrfProve(secretKey, alpha);

  /// proof_to_hash: returns the 64-byte VRF output beta for a proof.
  Uint8List proofToHash(Uint8List proof) => _l.ecvrfProofToHash(proof);

  /// Verify: returns the 64-byte beta on success; throws if the proof is invalid.
  Uint8List verify(Uint8List publicKey, Uint8List alpha, Uint8List proof) =>
      _l.ecvrfVerify(publicKey, alpha, proof);
}
