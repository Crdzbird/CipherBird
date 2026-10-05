part of '../../cryptolib.dart';

final class CryptoAsymBundle extends Struct {
  external CryptoBuffer boxPublic;
  external CryptoBuffer boxSecret;
  external CryptoBuffer signPublic;
  external CryptoBuffer signSecret;
}
