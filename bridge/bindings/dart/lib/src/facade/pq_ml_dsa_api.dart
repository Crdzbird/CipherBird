part of '../../cryptolib_ffi.dart';

/// ML-DSA (FIPS 204) signatures.
extension type PqMlDsaApi(CryptoLib _l) {
  KeyPairResult keygen(MlDsaLevel level) => _l.mlDsaKeygen(level);

  Uint8List sign(Uint8List msg, Uint8List secretKey, MlDsaLevel level) =>
      _l.mlDsaSign(msg, secretKey, level);

  bool verify(Uint8List msg, Uint8List sig, Uint8List publicKey,
          MlDsaLevel level) =>
      _l.mlDsaVerify(msg, sig, publicKey, level);
}
