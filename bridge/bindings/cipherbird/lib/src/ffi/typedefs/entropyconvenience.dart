part of '../../cipher_bird.dart';

typedef _KeyFromFileC = CipherBirdBufferResult Function(Pointer<Utf8> path);
typedef _KeyFromFileDart = CipherBirdBufferResult Function(Pointer<Utf8> path);
typedef _SealFromFileC =
    CipherBirdPacket Function(
      Pointer<Utf8> path,
      Pointer<Utf8> pt,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _SealFromFileDart =
    CipherBirdPacket Function(
      Pointer<Utf8> path,
      Pointer<Utf8> pt,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _OpenFromFileC =
    CipherBirdBufferResult Function(
      Pointer<Utf8> path,
      Pointer<CipherBirdPacket> pkt,
      Pointer<Utf8> aad,
    );
typedef _OpenFromFileDart =
    CipherBirdBufferResult Function(
      Pointer<Utf8> path,
      Pointer<CipherBirdPacket> pkt,
      Pointer<Utf8> aad,
    );
