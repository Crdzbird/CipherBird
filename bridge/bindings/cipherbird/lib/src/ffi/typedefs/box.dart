part of '../../cryptolib.dart';

typedef _BoxKeygenC = CryptoKeyPair Function();
typedef _BoxKeygenDart = CryptoKeyPair Function();
typedef _BoxEncryptC =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> recipientPub,
      Size rpubLen,
      Pointer<Uint8> senderSec,
      Size ssecLen,
    );
typedef _BoxEncryptDart =
    CryptoBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> recipientPub,
      int rpubLen,
      Pointer<Uint8> senderSec,
      int ssecLen,
    );
typedef _BoxDecryptC =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> senderPub,
      Size spubLen,
      Pointer<Uint8> recipientSec,
      Size rsecLen,
    );
typedef _BoxDecryptDart =
    CryptoBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> senderPub,
      int spubLen,
      Pointer<Uint8> recipientSec,
      int rsecLen,
    );
