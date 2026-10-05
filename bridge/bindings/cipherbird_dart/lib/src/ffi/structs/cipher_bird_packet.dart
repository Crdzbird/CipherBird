part of '../../cipher_bird.dart';

final class CipherBirdPacket extends Struct {
  external CipherBirdBuffer ciphertext;
  external CipherBirdBuffer signature;
  external CipherBirdBuffer kdfSalt;
}
