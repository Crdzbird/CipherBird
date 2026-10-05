part of '../../cipher_bird.dart';

typedef _X25519KeygenC = CipherBirdKeyPair Function();
typedef _X25519KeygenDart = CipherBirdKeyPair Function();
typedef _X25519SharedSecretC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ourSecret,
      Size ourLen,
      Pointer<Uint8> theirPublic,
      Size theirLen,
    );
typedef _X25519SharedSecretDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ourSecret,
      int ourLen,
      Pointer<Uint8> theirPublic,
      int theirLen,
    );
