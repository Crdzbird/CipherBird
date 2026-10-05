part of '../../cryptolib.dart';

typedef _Ed25519KeygenC = CryptoKeyPair Function();
typedef _Ed25519KeygenDart = CryptoKeyPair Function();
typedef _Ed25519KeygenFromSeedC =
    CryptoKeyPair Function(Pointer<Uint8> seed, Size seedLen);
typedef _Ed25519KeygenFromSeedDart =
    CryptoKeyPair Function(Pointer<Uint8> seed, int seedLen);
typedef _Ed25519SignC =
    CryptoBufferResult Function(
      Pointer<Uint8> msg,
      Size msgLen,
      Pointer<Uint8> sk,
      Size skLen,
    );
typedef _Ed25519SignDart =
    CryptoBufferResult Function(
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
