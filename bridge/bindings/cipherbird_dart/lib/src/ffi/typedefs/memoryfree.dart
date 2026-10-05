part of '../../cipher_bird.dart';

typedef _BufferFreeC = Void Function(Pointer<CipherBirdBuffer> buf);
typedef _BufferFreeDart = void Function(Pointer<CipherBirdBuffer> buf);
typedef _StrFreeC = Void Function(Pointer<Utf8> str);
typedef _StrFreeDart = void Function(Pointer<Utf8> str);
