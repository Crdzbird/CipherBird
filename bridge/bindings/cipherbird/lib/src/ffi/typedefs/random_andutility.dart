part of '../../cipher_bird.dart';

typedef _RandomBytesC = CryptoBufferResult Function(Size n);
typedef _RandomBytesDart = CryptoBufferResult Function(int n);
typedef _SecureEqualC =
    Int32 Function(Pointer<Uint8> a, Size aLen, Pointer<Uint8> b, Size bLen);
typedef _SecureEqualDart =
    int Function(Pointer<Uint8> a, int aLen, Pointer<Uint8> b, int bLen);
