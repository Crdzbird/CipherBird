part of '../../cipher_bird.dart';

/// Importing a P-256 private key from PKCS#8; see [CipherBirdP256].
extension CipherBirdP256Import on CipherBird {
  /// Imports an unencrypted PKCS#8 private key in DER and returns its secret
  /// key with the public key derived from it. The parse is strict: trailing
  /// bytes, another curve or algorithm, an encrypted PKCS#8, attributes, a
  /// scalar out of range and an embedded public key that does not belong to
  /// the scalar all throw. Wipe the secret key when done.
  KeyPairResult p256PrivateKeyFromPkcs8(Uint8List der) =>
      _p256Split(_p256Bytes('cryptolib_p256_import_pkcs8_der', der));

  /// [p256PrivateKeyFromPkcs8] on one PEM block labelled `PRIVATE KEY`, the
  /// `.p8` file Apple issues for push. Only whitespace may surround the
  /// block; `ENCRYPTED PRIVATE KEY` and `EC PRIVATE KEY` blocks are refused
  /// by name.
  KeyPairResult p256PrivateKeyFromPem(String pem) {
    final text = Uint8List.fromList(utf8.encode(pem));
    try {
      return _p256Split(_p256Bytes('cryptolib_p256_import_pkcs8_pem', text));
    } finally {
      text.fillRange(0, text.length, 0);
    }
  }

  KeyPairResult _p256Split(Uint8List both) {
    try {
      return KeyPairResult(
        publicKey: Uint8List.fromList(both.sublist(32)),
        secretKey: Uint8List.fromList(both.sublist(0, 32)),
      );
    } finally {
      both.fillRange(0, both.length, 0);
    }
  }
}
