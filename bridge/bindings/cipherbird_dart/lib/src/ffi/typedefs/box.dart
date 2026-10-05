part of '../../cipher_bird.dart';

typedef _BoxKeygenC = CipherBirdKeyPair Function();
typedef _BoxKeygenDart = CipherBirdKeyPair Function();
typedef _BoxEncryptC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Uint8> recipientPub,
      Size rpubLen,
      Pointer<Uint8> senderSec,
      Size ssecLen,
    );
typedef _BoxEncryptDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Uint8> recipientPub,
      int rpubLen,
      Pointer<Uint8> senderSec,
      int ssecLen,
    );
typedef _BoxDecryptC =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ct,
      Size ctLen,
      Pointer<Uint8> senderPub,
      Size spubLen,
      Pointer<Uint8> recipientSec,
      Size rsecLen,
    );
typedef _BoxDecryptDart =
    CipherBirdBufferResult Function(
      Pointer<Uint8> ct,
      int ctLen,
      Pointer<Uint8> senderPub,
      int spubLen,
      Pointer<Uint8> recipientSec,
      int rsecLen,
    );
