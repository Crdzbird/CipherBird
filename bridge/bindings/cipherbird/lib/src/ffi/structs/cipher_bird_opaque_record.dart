part of '../../cipher_bird.dart';

final class CipherBirdOpaqueRecord extends Struct {
  external CipherBirdBuffer record;
  external CipherBirdBuffer exportKey;
  external Pointer<Utf8> error;
}
