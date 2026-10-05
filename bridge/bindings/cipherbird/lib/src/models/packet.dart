part of '../cipher_bird.dart';

final class Packet {
  final Uint8List ciphertext;
  final Uint8List signature;
  final Uint8List kdfSalt;

  Packet({
    required this.ciphertext,
    required this.signature,
    required this.kdfSalt,
  });
}
