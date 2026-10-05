part of '../../cipher_bird.dart';

final class CryptoKemEncapsResult extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer sharedSecret;
}
