part of '../../cipher_bird.dart';

final class CryptoAsymBundle extends Struct {
  external CryptoBuffer boxPublic;
  external CryptoBuffer boxSecret;
  external CryptoBuffer signPublic;
  external CryptoBuffer signSecret;
}
