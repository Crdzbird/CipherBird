part of '../../cipher_bird.dart';

typedef _AsymBundleGenerateC = CipherBirdAsymBundle Function();
typedef _AsymBundleGenerateDart = CipherBirdAsymBundle Function();
typedef _AsymVaultSealC =
    CipherBirdPacket Function(
      Pointer<CipherBirdAsymBundle> sender,
      Pointer<Uint8> recipientBoxPub,
      Size rpubLen,
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _AsymVaultSealDart =
    CipherBirdPacket Function(
      Pointer<CipherBirdAsymBundle> sender,
      Pointer<Uint8> recipientBoxPub,
      int rpubLen,
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _AsymVaultOpenC =
    CipherBirdBufferResult Function(
      Pointer<CipherBirdPacket> pkt,
      Pointer<CipherBirdAsymBundle> recipient,
      Pointer<Uint8> senderSignPub,
      Size spubLen,
      Pointer<Utf8> aad,
    );
typedef _AsymVaultOpenDart =
    CipherBirdBufferResult Function(
      Pointer<CipherBirdPacket> pkt,
      Pointer<CipherBirdAsymBundle> recipient,
      Pointer<Uint8> senderSignPub,
      int spubLen,
      Pointer<Utf8> aad,
    );
