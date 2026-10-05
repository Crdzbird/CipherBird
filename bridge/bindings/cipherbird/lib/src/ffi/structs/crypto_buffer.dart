part of '../../cipher_bird.dart';

final class CryptoBuffer extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;
}
