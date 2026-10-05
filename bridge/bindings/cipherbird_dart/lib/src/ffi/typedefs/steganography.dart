part of '../../cipher_bird.dart';

typedef _StegoEmbedC =
    CryptoResult Function(
      Pointer<Utf8> cover,
      Pointer<Uint8> payload,
      Size payloadLen,
      Pointer<Utf8> output,
    );
typedef _StegoEmbedDart =
    CryptoResult Function(
      Pointer<Utf8> cover,
      Pointer<Uint8> payload,
      int payloadLen,
      Pointer<Utf8> output,
    );
typedef _StegoExtractC = CryptoBufferResult Function(Pointer<Utf8> path);
typedef _StegoExtractDart = CryptoBufferResult Function(Pointer<Utf8> path);
typedef _StegoCapacityC = Size Function(Pointer<Utf8> path);
typedef _StegoCapacityDart = int Function(Pointer<Utf8> path);
