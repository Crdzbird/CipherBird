part of '../cipher_bird.dart';

/// Ed25519. Supply [secretKey] to sign, [publicKey] to verify, or both.
final class Ed25519Signature extends SignatureScheme with _Builtin {
  const Ed25519Signature({this.secretKey, this.publicKey});
  final Uint8List? secretKey;
  final Uint8List? publicKey;
  @override
  int get id => 1;
  @override
  String get label => 'ed25519';
  @override
  Uint8List sign(CipherBird lib, Uint8List m) => lib.ed25519Sign(
    m,
    secretKey ??
        (throw StateError('cipherbird: Ed25519Signature has no secret key')),
  );
  @override
  bool verify(CipherBird lib, Uint8List m, Uint8List sig) => lib.ed25519Verify(
    m,
    sig,
    publicKey ??
        (throw StateError('cipherbird: Ed25519Signature has no public key')),
  );
}
