part of '../../cryptolib.dart';

typedef _StreamEncCreateC = Pointer<Void> Function(Pointer<Uint8> key);
typedef _StreamEncCreateDart = Pointer<Void> Function(Pointer<Uint8> key);
typedef _StreamEncHeaderC = CryptoBufferResult Function(Pointer<Void> h);
typedef _StreamEncHeaderDart = CryptoBufferResult Function(Pointer<Void> h);
typedef _StreamEncPushC =
    CryptoBufferResult Function(
      Pointer<Void> h,
      Pointer<Uint8> pt,
      Size ptLen,
      Uint8 tag,
    );
typedef _StreamEncPushDart =
    CryptoBufferResult Function(
      Pointer<Void> h,
      Pointer<Uint8> pt,
      int ptLen,
      int tag,
    );
typedef _StreamEncFreeC = Void Function(Pointer<Void> h);
typedef _StreamEncFreeDart = void Function(Pointer<Void> h);
typedef _StreamDecCreateC =
    Pointer<Void> Function(Pointer<Uint8> key, Pointer<Uint8> header);
typedef _StreamDecCreateDart =
    Pointer<Void> Function(Pointer<Uint8> key, Pointer<Uint8> header);
typedef _StreamDecPullC =
    CryptoBufferResult Function(
      Pointer<Void> h,
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> outTag,
    );
typedef _StreamDecPullDart =
    CryptoBufferResult Function(
      Pointer<Void> h,
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> outTag,
    );
typedef _StreamDecFreeC = Void Function(Pointer<Void> h);
typedef _StreamDecFreeDart = void Function(Pointer<Void> h);
