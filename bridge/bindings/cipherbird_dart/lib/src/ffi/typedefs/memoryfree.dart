part of '../../cryptolib.dart';

typedef _BufferFreeC = Void Function(Pointer<CryptoBuffer> buf);
typedef _BufferFreeDart = void Function(Pointer<CryptoBuffer> buf);
typedef _StrFreeC = Void Function(Pointer<Utf8> str);
typedef _StrFreeDart = void Function(Pointer<Utf8> str);
