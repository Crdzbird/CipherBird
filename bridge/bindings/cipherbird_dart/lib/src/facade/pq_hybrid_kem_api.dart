part of '../cipher_bird.dart';

/// X25519 + ML-KEM-768 hybrid KEM.
extension type PqHybridKemApi(CipherBird _l) {
  KeyPairResult keygen() => _l.hybridKemKeygen();

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Uint8List publicKey) =>
      _l.hybridKemEncapsulate(publicKey);

  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) =>
      _l.hybridKemDecapsulate(ciphertext, secretKey);
}
