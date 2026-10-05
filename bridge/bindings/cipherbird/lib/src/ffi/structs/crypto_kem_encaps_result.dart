part of '../../cryptolib.dart';

final class CryptoKemEncapsResult extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer sharedSecret;
}
