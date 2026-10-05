part of '../cipher_bird.dart';

/// KeyPairResult holds a public/secret key pair.
final class KeyPairResult {
  final Uint8List publicKey;
  final Uint8List secretKey;

  KeyPairResult({required this.publicKey, required this.secretKey});
}
