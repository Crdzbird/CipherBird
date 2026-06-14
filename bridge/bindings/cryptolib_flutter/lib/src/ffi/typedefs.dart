part of '../cryptolib.dart';

// Native function signatures (C + Dart) for each bound symbol (internal).

typedef _InitC = Int32 Function();
typedef _InitDart = int Function();

typedef _VersionC = Pointer<Utf8> Function();
typedef _VersionDart = Pointer<Utf8> Function();

// -- Random & utility --
typedef _RandomBytesC = CryptoBufferResult Function(Size n);
typedef _RandomBytesDart = CryptoBufferResult Function(int n);

typedef _SecureEqualC = Int32 Function(
    Pointer<Uint8> a, Size aLen, Pointer<Uint8> b, Size bLen);
typedef _SecureEqualDart = int Function(
    Pointer<Uint8> a, int aLen, Pointer<Uint8> b, int bLen);

// -- Memory free --
typedef _BufferFreeC = Void Function(Pointer<CryptoBuffer> buf);
typedef _BufferFreeDart = void Function(Pointer<CryptoBuffer> buf);

typedef _StrFreeC = Void Function(Pointer<Utf8> str);
typedef _StrFreeDart = void Function(Pointer<Utf8> str);

// -- Hashing --
typedef _Blake2bC = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Pointer<Uint8> key, Size keyLen);
typedef _Blake2bDart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> key, int keyLen);

typedef _Sha256C = CryptoBufferResult Function(Pointer<Uint8> msg, Size msgLen);
typedef _Sha256Dart = CryptoBufferResult Function(Pointer<Uint8> msg, int msgLen);

typedef _Sha512C = CryptoBufferResult Function(Pointer<Uint8> msg, Size msgLen);
typedef _Sha512Dart = CryptoBufferResult Function(Pointer<Uint8> msg, int msgLen);

typedef _HmacSha512C = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Pointer<Uint8> key, Size keyLen);
typedef _HmacSha512Dart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> key, int keyLen);

typedef _HmacSha512VerifyC = Int32 Function(
    Pointer<Uint8> msg, Size msgLen,
    Pointer<Uint8> mac, Size macLen,
    Pointer<Uint8> key, Size keyLen);
typedef _HmacSha512VerifyDart = int Function(
    Pointer<Uint8> msg, int msgLen,
    Pointer<Uint8> mac, int macLen,
    Pointer<Uint8> key, int keyLen);

// -- Argon2id --
typedef _Argon2idHashStrC = CryptoBufferResult Function(
    Pointer<Utf8> password, Uint64 ops, Size mem);
typedef _Argon2idHashStrDart = CryptoBufferResult Function(
    Pointer<Utf8> password, int ops, int mem);

typedef _Argon2idVerifyStrC = Int32 Function(
    Pointer<Utf8> password, Pointer<Utf8> phcStr);
typedef _Argon2idVerifyStrDart = int Function(
    Pointer<Utf8> password, Pointer<Utf8> phcStr);

typedef _Argon2idDeriveC = CryptoBufferResult Function(
    Pointer<Utf8> password, Pointer<Uint8> salt, Size saltLen,
    Size keyLen, Uint64 ops, Size mem);
typedef _Argon2idDeriveDart = CryptoBufferResult Function(
    Pointer<Utf8> password, Pointer<Uint8> salt, int saltLen,
    int keyLen, int ops, int mem);

// -- Symmetric encryption --
typedef _SymKeygenC = CryptoBufferResult Function();
typedef _SymKeygenDart = CryptoBufferResult Function();

typedef _XChaCha20EncC = CryptoBufferResult Function(
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Uint8> key, Size keyLen,
    Pointer<Uint8> aad, Size aadLen);
typedef _XChaCha20EncDart = CryptoBufferResult Function(
    Pointer<Uint8> pt, int ptLen,
    Pointer<Uint8> key, int keyLen,
    Pointer<Uint8> aad, int aadLen);

typedef _XChaCha20DecC = CryptoBufferResult Function(
    Pointer<Uint8> ct, Size ctLen,
    Pointer<Uint8> key, Size keyLen,
    Pointer<Uint8> aad, Size aadLen);
typedef _XChaCha20DecDart = CryptoBufferResult Function(
    Pointer<Uint8> ct, int ctLen,
    Pointer<Uint8> key, int keyLen,
    Pointer<Uint8> aad, int aadLen);

typedef _Aes256GcmEncC = CryptoBufferResult Function(
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Uint8> key, Size keyLen,
    Pointer<Uint8> aad, Size aadLen);
typedef _Aes256GcmEncDart = CryptoBufferResult Function(
    Pointer<Uint8> pt, int ptLen,
    Pointer<Uint8> key, int keyLen,
    Pointer<Uint8> aad, int aadLen);

typedef _Aes256GcmDecC = CryptoBufferResult Function(
    Pointer<Uint8> ct, Size ctLen,
    Pointer<Uint8> key, Size keyLen,
    Pointer<Uint8> aad, Size aadLen);
typedef _Aes256GcmDecDart = CryptoBufferResult Function(
    Pointer<Uint8> ct, int ctLen,
    Pointer<Uint8> key, int keyLen,
    Pointer<Uint8> aad, int aadLen);

typedef _Aes256GcmAvailableC = Int32 Function();
typedef _Aes256GcmAvailableDart = int Function();

// -- SecretStream --
typedef _StreamEncCreateC = Pointer<Void> Function(Pointer<Uint8> key);
typedef _StreamEncCreateDart = Pointer<Void> Function(Pointer<Uint8> key);

typedef _StreamEncHeaderC = CryptoBufferResult Function(Pointer<Void> h);
typedef _StreamEncHeaderDart = CryptoBufferResult Function(Pointer<Void> h);

typedef _StreamEncPushC = CryptoBufferResult Function(
    Pointer<Void> h, Pointer<Uint8> pt, Size ptLen, Uint8 tag);
typedef _StreamEncPushDart = CryptoBufferResult Function(
    Pointer<Void> h, Pointer<Uint8> pt, int ptLen, int tag);

typedef _StreamEncFreeC = Void Function(Pointer<Void> h);
typedef _StreamEncFreeDart = void Function(Pointer<Void> h);

typedef _StreamDecCreateC = Pointer<Void> Function(
    Pointer<Uint8> key, Pointer<Uint8> header);
typedef _StreamDecCreateDart = Pointer<Void> Function(
    Pointer<Uint8> key, Pointer<Uint8> header);

typedef _StreamDecPullC = CryptoBufferResult Function(
    Pointer<Void> h, Pointer<Uint8> ct, Size ctLen, Pointer<Uint8> outTag);
typedef _StreamDecPullDart = CryptoBufferResult Function(
    Pointer<Void> h, Pointer<Uint8> ct, int ctLen, Pointer<Uint8> outTag);

typedef _StreamDecFreeC = Void Function(Pointer<Void> h);
typedef _StreamDecFreeDart = void Function(Pointer<Void> h);

// -- Ed25519 --
typedef _Ed25519KeygenC = CryptoKeyPair Function();
typedef _Ed25519KeygenDart = CryptoKeyPair Function();

typedef _Ed25519KeygenFromSeedC = CryptoKeyPair Function(
    Pointer<Uint8> seed, Size seedLen);
typedef _Ed25519KeygenFromSeedDart = CryptoKeyPair Function(
    Pointer<Uint8> seed, int seedLen);

typedef _Ed25519SignC = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Pointer<Uint8> sk, Size skLen);
typedef _Ed25519SignDart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> sk, int skLen);

typedef _Ed25519VerifyC = Int32 Function(
    Pointer<Uint8> msg, Size msgLen,
    Pointer<Uint8> sig, Size sigLen,
    Pointer<Uint8> pk, Size pkLen);
typedef _Ed25519VerifyDart = int Function(
    Pointer<Uint8> msg, int msgLen,
    Pointer<Uint8> sig, int sigLen,
    Pointer<Uint8> pk, int pkLen);

// -- X25519 --
typedef _X25519KeygenC = CryptoKeyPair Function();
typedef _X25519KeygenDart = CryptoKeyPair Function();

typedef _X25519SharedSecretC = CryptoBufferResult Function(
    Pointer<Uint8> ourSecret, Size ourLen,
    Pointer<Uint8> theirPublic, Size theirLen);
typedef _X25519SharedSecretDart = CryptoBufferResult Function(
    Pointer<Uint8> ourSecret, int ourLen,
    Pointer<Uint8> theirPublic, int theirLen);

// -- Box --
typedef _BoxKeygenC = CryptoKeyPair Function();
typedef _BoxKeygenDart = CryptoKeyPair Function();

typedef _BoxEncryptC = CryptoBufferResult Function(
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Uint8> recipientPub, Size rpubLen,
    Pointer<Uint8> senderSec, Size ssecLen);
typedef _BoxEncryptDart = CryptoBufferResult Function(
    Pointer<Uint8> pt, int ptLen,
    Pointer<Uint8> recipientPub, int rpubLen,
    Pointer<Uint8> senderSec, int ssecLen);

typedef _BoxDecryptC = CryptoBufferResult Function(
    Pointer<Uint8> ct, Size ctLen,
    Pointer<Uint8> senderPub, Size spubLen,
    Pointer<Uint8> recipientSec, Size rsecLen);
typedef _BoxDecryptDart = CryptoBufferResult Function(
    Pointer<Uint8> ct, int ctLen,
    Pointer<Uint8> senderPub, int spubLen,
    Pointer<Uint8> recipientSec, int rsecLen);

// -- SealedBox --
typedef _SealedBoxEncryptC = CryptoBufferResult Function(
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Uint8> recipientPub, Size rpubLen);
typedef _SealedBoxEncryptDart = CryptoBufferResult Function(
    Pointer<Uint8> pt, int ptLen,
    Pointer<Uint8> recipientPub, int rpubLen);

typedef _SealedBoxDecryptC = CryptoBufferResult Function(
    Pointer<Uint8> ct, Size ctLen,
    Pointer<Uint8> recipientPub, Size rpubLen,
    Pointer<Uint8> recipientSec, Size rsecLen);
typedef _SealedBoxDecryptDart = CryptoBufferResult Function(
    Pointer<Uint8> ct, int ctLen,
    Pointer<Uint8> recipientPub, int rpubLen,
    Pointer<Uint8> recipientSec, int rsecLen);

// -- Vault --
typedef _VaultCreateC = Pointer<Void> Function(
    Pointer<Uint8> masterKey, Size mkLen, Int32 kdfPreset);
typedef _VaultCreateDart = Pointer<Void> Function(
    Pointer<Uint8> masterKey, int mkLen, int kdfPreset);

typedef _VaultFromEntropyC = Pointer<Void> Function(
    Pointer<Void> entropy, Int32 kdfPreset);
typedef _VaultFromEntropyDart = Pointer<Void> Function(
    Pointer<Void> entropy, int kdfPreset);

typedef _VaultSealC = CryptoPacket Function(
    Pointer<Void> vault,
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Utf8> aad, Pointer<Pointer<Utf8>> outError);
typedef _VaultSealDart = CryptoPacket Function(
    Pointer<Void> vault,
    Pointer<Uint8> pt, int ptLen,
    Pointer<Utf8> aad, Pointer<Pointer<Utf8>> outError);

typedef _VaultSealBoostedC = CryptoPacket Function(
    Pointer<Void> vault,
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Utf8> aad, Pointer<Void> boost,
    Pointer<Pointer<Utf8>> outError);
typedef _VaultSealBoostedDart = CryptoPacket Function(
    Pointer<Void> vault,
    Pointer<Uint8> pt, int ptLen,
    Pointer<Utf8> aad, Pointer<Void> boost,
    Pointer<Pointer<Utf8>> outError);

typedef _VaultOpenC = CryptoBufferResult Function(
    Pointer<Void> vault, Pointer<CryptoPacket> pkt, Pointer<Utf8> aad);
typedef _VaultOpenDart = CryptoBufferResult Function(
    Pointer<Void> vault, Pointer<CryptoPacket> pkt, Pointer<Utf8> aad);

typedef _VaultOpenBoostedC = CryptoBufferResult Function(
    Pointer<Void> vault, Pointer<CryptoPacket> pkt, Pointer<Utf8> aad,
    Pointer<Void> boost);
typedef _VaultOpenBoostedDart = CryptoBufferResult Function(
    Pointer<Void> vault, Pointer<CryptoPacket> pkt, Pointer<Utf8> aad,
    Pointer<Void> boost);

typedef _VaultPublicKeyC = CryptoBufferResult Function(Pointer<Void> vault);
typedef _VaultPublicKeyDart = CryptoBufferResult Function(Pointer<Void> vault);

typedef _PacketSerialiseC = CryptoBufferResult Function(Pointer<CryptoPacket> pkt);
typedef _PacketSerialiseDart = CryptoBufferResult Function(Pointer<CryptoPacket> pkt);

typedef _PacketDeserialiseC = CryptoPacket Function(
    Pointer<Uint8> data, Size len, Pointer<Pointer<Utf8>> outError);
typedef _PacketDeserialiseDart = CryptoPacket Function(
    Pointer<Uint8> data, int len, Pointer<Pointer<Utf8>> outError);

typedef _VaultFreeC = Void Function(Pointer<Void> vault);
typedef _VaultFreeDart = void Function(Pointer<Void> vault);

// -- Asymmetric Vault --
typedef _AsymBundleGenerateC = CryptoAsymBundle Function();
typedef _AsymBundleGenerateDart = CryptoAsymBundle Function();

typedef _AsymVaultSealC = CryptoPacket Function(
    Pointer<CryptoAsymBundle> sender,
    Pointer<Uint8> recipientBoxPub, Size rpubLen,
    Pointer<Uint8> pt, Size ptLen,
    Pointer<Utf8> aad, Pointer<Pointer<Utf8>> outError);
typedef _AsymVaultSealDart = CryptoPacket Function(
    Pointer<CryptoAsymBundle> sender,
    Pointer<Uint8> recipientBoxPub, int rpubLen,
    Pointer<Uint8> pt, int ptLen,
    Pointer<Utf8> aad, Pointer<Pointer<Utf8>> outError);

typedef _AsymVaultOpenC = CryptoBufferResult Function(
    Pointer<CryptoPacket> pkt,
    Pointer<CryptoAsymBundle> recipient,
    Pointer<Uint8> senderSignPub, Size spubLen,
    Pointer<Utf8> aad);
typedef _AsymVaultOpenDart = CryptoBufferResult Function(
    Pointer<CryptoPacket> pkt,
    Pointer<CryptoAsymBundle> recipient,
    Pointer<Uint8> senderSignPub, int spubLen,
    Pointer<Utf8> aad);

// -- Entropy --
typedef _EntropyFromFileC = Pointer<Void> Function(
    Pointer<Utf8> path, Pointer<Pointer<Utf8>> outError);
typedef _EntropyFromFileDart = Pointer<Void> Function(
    Pointer<Utf8> path, Pointer<Pointer<Utf8>> outError);

typedef _EntropyFromFilesC = Pointer<Void> Function(
    Pointer<Pointer<Utf8>> paths, Size count, Pointer<Pointer<Utf8>> outError);
typedef _EntropyFromFilesDart = Pointer<Void> Function(
    Pointer<Pointer<Utf8>> paths, int count, Pointer<Pointer<Utf8>> outError);

typedef _EntropyDeriveAllC = CryptoDerivedKeys Function(Pointer<Void> h);
typedef _EntropyDeriveAllDart = CryptoDerivedKeys Function(Pointer<Void> h);

typedef _EntropySymKeyC = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropySymKeyDart = CryptoBufferResult Function(Pointer<Void> h);

typedef _EntropyRawC = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyRawDart = CryptoBufferResult Function(Pointer<Void> h);

typedef _EntropyBoostC = CryptoBufferResult Function(Pointer<Void> h);
typedef _EntropyBoostDart = CryptoBufferResult Function(Pointer<Void> h);

typedef _EntropyInfoC = CryptoEntropyInfo Function(Pointer<Void> h);
typedef _EntropyInfoDart = CryptoEntropyInfo Function(Pointer<Void> h);

typedef _EntropyAsymBundleC = CryptoAsymBundle Function(
    Pointer<Void> h, Pointer<Pointer<Utf8>> outError);
typedef _EntropyAsymBundleDart = CryptoAsymBundle Function(
    Pointer<Void> h, Pointer<Pointer<Utf8>> outError);

typedef _EntropyRefreshC = Void Function(Pointer<Void> h);
typedef _EntropyRefreshDart = void Function(Pointer<Void> h);

typedef _EntropyFreeC = Void Function(Pointer<Void> h);
typedef _EntropyFreeDart = void Function(Pointer<Void> h);

// -- Entropy convenience --
typedef _KeyFromFileC = CryptoBufferResult Function(Pointer<Utf8> path);
typedef _KeyFromFileDart = CryptoBufferResult Function(Pointer<Utf8> path);

typedef _SealFromFileC = CryptoPacket Function(
    Pointer<Utf8> path, Pointer<Utf8> pt, Pointer<Utf8> aad,
    Pointer<Pointer<Utf8>> outError);
typedef _SealFromFileDart = CryptoPacket Function(
    Pointer<Utf8> path, Pointer<Utf8> pt, Pointer<Utf8> aad,
    Pointer<Pointer<Utf8>> outError);

typedef _OpenFromFileC = CryptoBufferResult Function(
    Pointer<Utf8> path, Pointer<CryptoPacket> pkt, Pointer<Utf8> aad);
typedef _OpenFromFileDart = CryptoBufferResult Function(
    Pointer<Utf8> path, Pointer<CryptoPacket> pkt, Pointer<Utf8> aad);

// -- Steganography --
typedef _StegoEmbedC = CryptoResult Function(
    Pointer<Utf8> cover, Pointer<Uint8> payload, Size payloadLen,
    Pointer<Utf8> output);
typedef _StegoEmbedDart = CryptoResult Function(
    Pointer<Utf8> cover, Pointer<Uint8> payload, int payloadLen,
    Pointer<Utf8> output);

typedef _StegoExtractC = CryptoBufferResult Function(Pointer<Utf8> path);
typedef _StegoExtractDart = CryptoBufferResult Function(Pointer<Utf8> path);

typedef _StegoCapacityC = Size Function(Pointer<Utf8> path);
typedef _StegoCapacityDart = int Function(Pointer<Utf8> path);
