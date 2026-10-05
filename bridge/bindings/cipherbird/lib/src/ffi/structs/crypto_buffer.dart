part of '../../cryptolib.dart';

final class CryptoBuffer extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;
}
