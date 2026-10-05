part of '../../cipher_bird.dart';

final class CryptoFrostKeyGen extends Struct {
  external CryptoBuffer groupPublicKey;
  external CryptoBuffer secretShares;
  external CryptoBuffer publicShares;

  @Size()
  external int count;
  external Pointer<Utf8> error;
}
