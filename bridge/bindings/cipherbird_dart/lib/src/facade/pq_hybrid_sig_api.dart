part of '../cipher_bird.dart';

/// Ed25519 + ML-DSA-65 hybrid signatures.
extension type PqHybridSigApi(CipherBird _l) {
  KeyPairResult keygen() => _l.hybridSigKeygen();

  Uint8List sign(Uint8List msg, Uint8List secretKey) =>
      _l.hybridSigSign(msg, secretKey);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey) =>
      _l.hybridSigVerify(msg, sig, publicKey);
}
