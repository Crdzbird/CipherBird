part of '../../cipher_bird.dart';

typedef _StegoEmbedC =
    CipherBirdResult Function(
      Pointer<Utf8> cover,
      Pointer<Uint8> payload,
      Size payloadLen,
      Pointer<Utf8> output,
    );
typedef _StegoEmbedDart =
    CipherBirdResult Function(
      Pointer<Utf8> cover,
      Pointer<Uint8> payload,
      int payloadLen,
      Pointer<Utf8> output,
    );
typedef _StegoExtractC = CipherBirdBufferResult Function(Pointer<Utf8> path);
typedef _StegoExtractDart = CipherBirdBufferResult Function(Pointer<Utf8> path);
typedef _StegoCapacityC = Size Function(Pointer<Utf8> path);
typedef _StegoCapacityDart = int Function(Pointer<Utf8> path);
