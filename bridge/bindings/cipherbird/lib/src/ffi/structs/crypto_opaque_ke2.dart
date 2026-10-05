part of '../../cryptolib.dart';

final class CryptoOpaqueKe2 extends Struct {
  external CryptoBuffer ke2;
  external CryptoBuffer serverState;
  external Pointer<Utf8> error;
}
