part of '../../cipher_bird.dart';

typedef _Ed25519KeygenC = CipherBirdKeyPair Function();
typedef _Ed25519KeygenDart = CipherBirdKeyPair Function();
typedef _Ed25519KeygenFromSeedC =
    CipherBirdKeyPair Function(Pointer<Uint8> seed, Size seedLen);
typedef _Ed25519KeygenFromSeedDart =
    CipherBirdKeyPair Function(Pointer<Uint8> seed, int seedLen);
typedef _Ed25519SignC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> msg,
      Size msgLen,
      Pointer<Uint8> sk,
      Size skLen,
    );
typedef _Ed25519SignDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> msg,
      int msgLen,
      Pointer<Uint8> sk,
      int skLen,
    );
typedef _Ed25519VerifyC =
    Int32 Function(
      Pointer<Uint8> msg,
      Size msgLen,
      Pointer<Uint8> sig,
      Size sigLen,
      Pointer<Uint8> pk,
      Size pkLen,
    );
typedef _Ed25519VerifyDart =
    int Function(
      Pointer<Uint8> msg,
      int msgLen,
      Pointer<Uint8> sig,
      int sigLen,
      Pointer<Uint8> pk,
      int pkLen,
    );
