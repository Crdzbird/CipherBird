part of '../../cryptolib.dart';

final class CryptoKeyPair extends Struct {
  external CryptoBuffer publicKey;
  external CryptoBuffer secretKey;
}
