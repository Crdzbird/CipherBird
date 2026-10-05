part of '../../cryptolib.dart';

typedef _SealedBoxEncryptC =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> recipientPub,
      Size rpubLen,
    );
typedef _SealedBoxEncryptDart =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> recipientPub,
      int rpubLen,
    );
typedef _SealedBoxDecryptC =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> recipientPub,
      Size rpubLen,
      Pointer<Uint8> recipientSec,
      Size rsecLen,
    );
typedef _SealedBoxDecryptDart =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> recipientPub,
      int rpubLen,
      Pointer<Uint8> recipientSec,
      int rsecLen,
    );
