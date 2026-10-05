part of '../../cipher_bird.dart';

final class CipherBirdAsymBundle extends Struct {
  external CipherBirdBuffer boxPublic;
  external CipherBirdBuffer boxSecret;
  external CipherBirdBuffer signPublic;
  external CipherBirdBuffer signSecret;
}
