part of '../cryptolib.dart';

/// X25519 + sntrup761 hybrid KEM (a second lattice family).
extension type PqSntrupApi(CryptoLib _l) {
  KeyPairResult keygen() => _l.sntrupX25519Keygen();

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) encapsulate(Uint8List publicKey) =>
      _l.sntrupX25519Encapsulate(publicKey);

  Uint8List decapsulate(Uint8List ciphertext, Uint8List secretKey) =>
      _l.sntrupX25519Decapsulate(ciphertext, secretKey);
}
