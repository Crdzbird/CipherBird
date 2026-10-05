part of '../../cipher_bird.dart';

final class CryptoPacket extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer signature;
  external CryptoBuffer kdfSalt;
}
