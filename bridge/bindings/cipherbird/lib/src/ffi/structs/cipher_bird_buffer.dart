part of '../../cipher_bird.dart';

final class CipherBirdBuffer extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;
}
