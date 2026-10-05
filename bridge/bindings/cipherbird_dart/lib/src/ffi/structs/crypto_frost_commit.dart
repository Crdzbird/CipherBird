part of '../../cipher_bird.dart';

final class CryptoFrostCommit extends Struct {
  external CryptoBuffer hidingNonce;
  external CryptoBuffer bindingNonce;
  external CryptoBuffer hidingCommit;
  external CryptoBuffer bindingCommit;
  external Pointer<Utf8> error;
}
