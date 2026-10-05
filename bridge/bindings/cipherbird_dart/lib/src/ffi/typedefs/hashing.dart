part of '../../cipher_bird.dart';

typedef _Blake2bC =
    CryptoBufferResult Function(
      Pointer<Uint8> msg,
      Size msgLen,
      Pointer<Uint8> key,
      Size keyLen,
    );
typedef _Blake2bDart =
    CryptoBufferResult Function(
      Pointer<Uint8> msg,
      int msgLen,
      Pointer<Uint8> key,
      int keyLen,
    );
typedef _Sha256C = CryptoBufferResult Function(Pointer<Uint8> msg, Size msgLen);
typedef _Sha256Dart =
    CryptoBufferResult Function(Pointer<Uint8> msg, int msgLen);
typedef _Sha512C = CryptoBufferResult Function(Pointer<Uint8> msg, Size msgLen);
typedef _Sha512Dart =
    CryptoBufferResult Function(Pointer<Uint8> msg, int msgLen);
typedef _HmacSha512C =
    CryptoBufferResult Function(
      Pointer<Uint8> msg,
      Size msgLen,
      Pointer<Uint8> key,
      Size keyLen,
    );
typedef _HmacSha512Dart =
    CryptoBufferResult Function(
      Pointer<Uint8> msg,
      int msgLen,
      Pointer<Uint8> key,
      int keyLen,
    );
typedef _HmacSha512VerifyC =
    Int32 Function(
      Pointer<Uint8> msg,
      Size msgLen,
      Pointer<Uint8> mac,
      Size macLen,
      Pointer<Uint8> key,
      Size keyLen,
    );
typedef _HmacSha512VerifyDart =
    int Function(
      Pointer<Uint8> msg,
      int msgLen,
      Pointer<Uint8> mac,
      int macLen,
      Pointer<Uint8> key,
      int keyLen,
    );
