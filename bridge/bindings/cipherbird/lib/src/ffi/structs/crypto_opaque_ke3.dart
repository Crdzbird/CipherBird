part of '../../cryptolib.dart';

final class CryptoOpaqueKe3 extends Struct {
  external CryptoBuffer ke3;
  external CryptoBuffer sessionKey;
  external CryptoBuffer exportKey;
  external Pointer<Utf8> error;
}
