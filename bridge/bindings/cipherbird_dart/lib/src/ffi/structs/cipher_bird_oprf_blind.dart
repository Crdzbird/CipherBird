part of '../../cipher_bird.dart';

final class CipherBirdOprfBlind extends Struct {
  external CipherBirdBuffer blind;
  external CipherBirdBuffer blindedElement;
  external Pointer<Utf8> error;
}
