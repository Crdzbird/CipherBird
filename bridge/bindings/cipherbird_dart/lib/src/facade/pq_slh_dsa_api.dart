part of '../cipher_bird.dart';

/// SLH-DSA (FIPS 205) hash-based signatures.
extension type PqSlhDsaApi(CipherBird _l) {
  KeyPairResult keygen(SlhDsaLevel level, SlhDsaHash hash) =>
      _l.slhDsaKeygen(level, hash);

  Uint8List sign(
    Uint8List msg,
    Uint8List secretKey,
    SlhDsaLevel level,
    SlhDsaHash hash,
  ) => _l.slhDsaSign(msg, secretKey, level, hash);

  bool verify(
    Uint8List msg,
    Uint8List sig,
    Uint8List publicKey,
    SlhDsaLevel level,
    SlhDsaHash hash,
  ) => _l.slhDsaVerify(msg, sig, publicKey, level, hash);
}
