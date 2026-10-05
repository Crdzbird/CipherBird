part of '../../cipher_bird.dart';

typedef _X25519KeygenC = CryptoKeyPair Function();
typedef _X25519KeygenDart = CryptoKeyPair Function();
typedef _X25519SharedSecretC =
    CryptoBufferResult Function(
      Pointer<Uint8> ourSecret,
      Size ourLen,
      Pointer<Uint8> theirPublic,
      Size theirLen,
    );
typedef _X25519SharedSecretDart =
    CryptoBufferResult Function(
      Pointer<Uint8> ourSecret,
      int ourLen,
      Pointer<Uint8> theirPublic,
      int theirLen,
    );
