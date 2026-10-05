part of '../cryptolib.dart';

/// ML-KEM (FIPS 203) key encapsulation.
extension type PqMlKemApi(CryptoLib _l) {
  KeyPairResult keygen(MlKemLevel level) => _l.mlKemKeygen(level);

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Uint8List publicKey, MlKemLevel level) =>
      _l.mlKemEncapsulate(publicKey, level);

  Uint8List decapsulate(
    Uint8List ciphertext,
    Uint8List secretKey,
    MlKemLevel level,
  ) => _l.mlKemDecapsulate(ciphertext, secretKey, level);
}
