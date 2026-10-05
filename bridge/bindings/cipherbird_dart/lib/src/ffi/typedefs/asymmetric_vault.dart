part of '../../cipher_bird.dart';

typedef _AsymBundleGenerateC = CryptoAsymBundle Function();
typedef _AsymBundleGenerateDart = CryptoAsymBundle Function();
typedef _AsymVaultSealC =
    CryptoPacket Function(
      Pointer<CryptoAsymBundle> sender,
      Pointer<Uint8> recipientBoxPub,
      Size rpubLen,
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _AsymVaultSealDart =
    CryptoPacket Function(
      Pointer<CryptoAsymBundle> sender,
      Pointer<Uint8> recipientBoxPub,
      int rpubLen,
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _AsymVaultOpenC =
    CryptoBufferResult Function(
      Pointer<CryptoPacket> pkt,
      Pointer<CryptoAsymBundle> recipient,
      Pointer<Uint8> senderSignPub,
      Size spubLen,
      Pointer<Utf8> aad,
    );
typedef _AsymVaultOpenDart =
    CryptoBufferResult Function(
      Pointer<CryptoPacket> pkt,
      Pointer<CryptoAsymBundle> recipient,
      Pointer<Uint8> senderSignPub,
      int spubLen,
      Pointer<Utf8> aad,
    );
