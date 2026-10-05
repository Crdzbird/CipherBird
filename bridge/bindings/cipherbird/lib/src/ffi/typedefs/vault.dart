part of '../../cryptolib.dart';

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
    CryptoPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultSealDart =
    CryptoPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Utf8> aad,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultSealBoostedC =
    CryptoPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      Size ptLen,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultSealBoostedDart =
    CryptoPacket Function(
      Pointer<Void> vault,
      Pointer<Uint8> pt,
      int ptLen,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultOpenC =
    CryptoBufferResult Function(
      Pointer<Void> vault,
      Pointer<CryptoPacket> pkt,
      Pointer<Utf8> aad,
    );
typedef _VaultOpenDart =
    CryptoBufferResult Function(
      Pointer<Void> vault,
      Pointer<CryptoPacket> pkt,
      Pointer<Utf8> aad,
    );
typedef _VaultOpenBoostedC =
    CryptoBufferResult Function(
      Pointer<Void> vault,
      Pointer<CryptoPacket> pkt,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
    );
typedef _VaultOpenBoostedDart =
    CryptoBufferResult Function(
      Pointer<Void> vault,
      Pointer<CryptoPacket> pkt,
      Pointer<Utf8> aad,
      Pointer<Void> boost,
    );
typedef _VaultPublicKeyC = CryptoBufferResult Function(Pointer<Void> vault);
typedef _VaultPublicKeyDart = CryptoBufferResult Function(Pointer<Void> vault);
typedef _PacketSerialiseC =
    CryptoBufferResult Function(Pointer<CryptoPacket> pkt);
typedef _PacketSerialiseDart =
    CryptoBufferResult Function(Pointer<CryptoPacket> pkt);
typedef _PacketDeserialiseC =
    CryptoPacket Function(
      Pointer<Uint8> data,
      Size len,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _PacketDeserialiseDart =
    CryptoPacket Function(
      Pointer<Uint8> data,
      int len,
      Pointer<Pointer<Utf8>> outError,
    );
typedef _VaultFreeC = Void Function(Pointer<Void> vault);
typedef _VaultFreeDart = void Function(Pointer<Void> vault);
