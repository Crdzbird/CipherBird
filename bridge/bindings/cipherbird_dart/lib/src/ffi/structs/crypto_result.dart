part of '../../cipher_bird.dart';

final class CryptoResult extends Struct {
  @Int32()
  external int ok;
  external Pointer<Utf8> error;
}
