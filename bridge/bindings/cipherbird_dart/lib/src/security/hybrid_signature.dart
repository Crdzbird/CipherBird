part of '../cipher_bird.dart';

/// Ed25519 + ML-DSA-65. A forgery needs breaking both families.
final class HybridSignature extends SignatureScheme with _Builtin {
  const HybridSignature({this.secretKey, this.publicKey});
  final Uint8List? secretKey;
  final Uint8List? publicKey;
  @override
  int get id => 2;
  @override
  String get label => 'hybrid';
  @override
  Uint8List sign(CipherBird lib, Uint8List m) => lib.hybridSigSign(
    m,
    secretKey ??
        (throw StateError('cipherbird: HybridSignature has no secret key')),
  );
  @override
  bool verify(CipherBird lib, Uint8List m, Uint8List sig) =>
      lib.hybridSigVerify(
        m,
        sig,
        publicKey ??
            (throw StateError('cipherbird: HybridSignature has no public key')),
      );
}
