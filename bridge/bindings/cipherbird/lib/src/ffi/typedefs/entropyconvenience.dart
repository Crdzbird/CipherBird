part of '../../cipher_bird.dart';

typedef _KeyFromFileC = CryptoBufferResult Function(Pointer<Utf8> path);
typedef _KeyFromFileDart = CryptoBufferResult Function(Pointer<Utf8> path);
typedef _SealFromFileC =
    CryptoPacket Function(
      Pointer<Utf8> path,
      Pointer<Utf8> pt,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _SealFromFileDart =
    CryptoPacket Function(
      Pointer<Utf8> path,
      Pointer<Utf8> pt,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _OpenFromFileC =
    CryptoBufferResult Function(
      Pointer<Utf8> path,
      Pointer<CryptoPacket> pkt,
      Pointer<Utf8> aad,
    );
typedef _OpenFromFileDart =
    CryptoBufferResult Function(
      Pointer<Utf8> path,
      Pointer<CryptoPacket> pkt,
      Pointer<Utf8> aad,
    );
