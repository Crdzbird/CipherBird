part of '../../cipher_bird.dart';

typedef _VaultCreateC =
    Pointer<Void> Function(
      Pointer<Uint8> masterKey,
      Size mkLen,
      Int32 kdfPreset,
    );
typedef _VaultCreateDart =
    Pointer<Void> Function(Pointer<Uint8> masterKey, int mkLen, int kdfPreset);
typedef _VaultFromEntropyC =
    Pointer<Void> Function(Pointer<Void> entropy, Int32 kdfPreset);
typedef _VaultFromEntropyDart =
    Pointer<Void> Function(Pointer<Void> entropy, int kdfPreset);
typedef _VaultSealC =
    CipherBirdPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultSealDart =
    CipherBirdPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultSealBoostedC =
    CipherBirdPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultSealBoostedDart =
    CipherBirdPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultOpenC =
    CipherBirdBufferResult Function(
      Pointer<Void> vault,
      Pointer<CipherBirdPacket> pkt,
      Pointer<Utf8> aad,
    );
typedef _VaultOpenDart =
    CipherBirdBufferResult Function(
      Pointer<Void> vault,
      Pointer<CipherBirdPacket> pkt,
      Pointer<Utf8> aad,
    );
typedef _VaultOpenBoostedC =
    CipherBirdBufferResult Function(
      Pointer<Void> vault,
      Pointer<CipherBirdPacket> pkt,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
    );
typedef _VaultOpenBoostedDart =
    CipherBirdBufferResult Function(
      Pointer<Void> vault,
      Pointer<CipherBirdPacket> pkt,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
    );
typedef _VaultPublicKeyC = CipherBirdBufferResult Function(Pointer<Void> vault);
typedef _VaultPublicKeyDart =
    CipherBirdBufferResult Function(Pointer<Void> vault);
typedef _PacketSerialiseC =
    CipherBirdBufferResult Function(Pointer<CipherBirdPacket> pkt);
typedef _PacketSerialiseDart =
    CipherBirdBufferResult Function(Pointer<CipherBirdPacket> pkt);
typedef _PacketDeserialiseC =
    CipherBirdPacket Function(
      Pointer<Uint8> data,
      Size len,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _PacketDeserialiseDart =
    CipherBirdPacket Function(
      Pointer<Uint8> data,
      int len,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultFreeC = Void Function(Pointer<Void> vault);
typedef _VaultFreeDart = void Function(Pointer<Void> vault);
