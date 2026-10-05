part of '../../cryptolib.dart';

final class CryptoOpaqueKe1 extends Struct {
  external CryptoBuffer ke1;
  external CryptoBuffer clientState;
  external Pointer<Utf8> error;
}
