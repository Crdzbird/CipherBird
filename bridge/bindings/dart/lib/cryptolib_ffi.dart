/// CryptoLib FFI bindings for Dart/Flutter.
///
/// Wraps the complete C FFI bridge (libcryptolib_c) via dart:ffi.
/// All 81 C functions are bound.
///
/// Usage:
/// ```dart
/// final lib = CryptoLib.load('/path/to/libcryptolib_c.dylib');
/// lib.init();
/// ```
library cryptolib_ffi;

import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

// =============================================================================
// C struct bindings
// =============================================================================

final class CryptoBuffer extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;
}

final class CryptoBufferResult extends Struct {
  external CryptoBuffer buf;
  external Pointer<Utf8> error;
}

final class CryptoResult extends Struct {
  @Int32()
  external int ok;
  external Pointer<Utf8> error;
}

final class CryptoPacket extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer signature;
  external CryptoBuffer kdfSalt;
}

final class CryptoKeyPair extends Struct {
  external CryptoBuffer publicKey;
  external CryptoBuffer secretKey;
}

final class CryptoKemEncapsResult extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer sharedSecret;
}

final class CryptoAsymBundle extends Struct {
  external CryptoBuffer boxPublic;
  external CryptoBuffer boxSecret;
  external CryptoBuffer signPublic;
  external CryptoBuffer signSecret;
}

final class CryptoDerivedKeys extends Struct {
  external CryptoBuffer symmetricKey;
  external CryptoBuffer vaultMasterKey;
  external CryptoBuffer signingSeed;
  external CryptoBuffer boxSeed;
  external CryptoBuffer streamKey;
  external CryptoBuffer rawEntropy;
}

final class CryptoEntropyInfo extends Struct {
  external Pointer<Utf8> path;

  @Uint64()
  external int fileSize;

  @Uint64()
  external int chunksRead;

  @Double()
  external double entropyBits;
}

// =============================================================================
// Native function typedefs (C signatures + Dart signatures)
// =============================================================================

// -- Init & version --
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

typedef _KeyPairFreeC = Void Function(Pointer<CryptoKeyPair> kp);
typedef _KeyPairFreeDart = void Function(Pointer<CryptoKeyPair> kp);

typedef _BundleFreeC = Void Function(Pointer<CryptoAsymBundle> b);
typedef _BundleFreeDart = void Function(Pointer<CryptoAsymBundle> b);

typedef _PacketFreeC = Void Function(Pointer<CryptoPacket> p);
typedef _PacketFreeDart = void Function(Pointer<CryptoPacket> p);

typedef _DerivedKeysFreeC = Void Function(Pointer<CryptoDerivedKeys> dk);
typedef _DerivedKeysFreeDart = void Function(Pointer<CryptoDerivedKeys> dk);

typedef _EntropyInfoFreeC = Void Function(Pointer<CryptoEntropyInfo> info);
typedef _EntropyInfoFreeDart = void Function(Pointer<CryptoEntropyInfo> info);

// -- Hashing --
typedef _Blake2bC = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Pointer<Uint8> key, Size keyLen);
typedef _Blake2bDart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> key, int keyLen);

typedef _Sha256C = CryptoBufferResult Function(Pointer<Uint8> msg, Size msgLen);
typedef _Sha256Dart = CryptoBufferResult Function(Pointer<Uint8> msg, int msgLen);

typedef _Sha512C = CryptoBufferResult Function(Pointer<Uint8> msg, Size msgLen);
typedef _Sha512Dart = CryptoBufferResult Function(Pointer<Uint8> msg, int msgLen);

// BLAKE3 — primary parallelizable hash, keyed MAC, and KDF (domain separation).
typedef _Blake3C = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Size outLen);
typedef _Blake3Dart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, int outLen);

typedef _Blake3KeyedC = CryptoBufferResult Function(
    Pointer<Uint8> msg, Size msgLen, Pointer<Uint8> key, Size keyLen, Size outLen);
typedef _Blake3KeyedDart = CryptoBufferResult Function(
    Pointer<Uint8> msg, int msgLen, Pointer<Uint8> key, int keyLen, int outLen);

typedef _Blake3DeriveKeyC = CryptoBufferResult Function(
    Pointer<Utf8> context, Pointer<Uint8> ikm, Size ikmLen, Size outLen);
typedef _Blake3DeriveKeyDart = CryptoBufferResult Function(
    Pointer<Utf8> context, Pointer<Uint8> ikm, int ikmLen, int outLen);

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

// =============================================================================
// High-level Dart types
// =============================================================================

/// Packet holds the output of a vault seal operation.
class Packet {
  final Uint8List ciphertext;
  final Uint8List signature;
  final Uint8List kdfSalt;

  Packet({
    required this.ciphertext,
    required this.signature,
    required this.kdfSalt,
  });
}

/// DerivedKeysResult holds 6 domain-separated keys from a media file.
class DerivedKeysResult {
  final Uint8List symmetricKey;
  final Uint8List vaultMasterKey;
  final Uint8List signingSeed;
  final Uint8List boxSeed;
  final Uint8List streamKey;
  final Uint8List rawEntropy;

  DerivedKeysResult({
    required this.symmetricKey,
    required this.vaultMasterKey,
    required this.signingSeed,
    required this.boxSeed,
    required this.streamKey,
    required this.rawEntropy,
  });
}

/// EntropyInfoResult holds metadata about an entropy source.
class EntropyInfoResult {
  final String path;
  final int fileSize;
  final int chunksRead;
  final double entropyBits;

  EntropyInfoResult({
    required this.path,
    required this.fileSize,
    required this.chunksRead,
    required this.entropyBits,
  });
}

/// KeyPairResult holds a public/secret key pair.
class KeyPairResult {
  final Uint8List publicKey;
  final Uint8List secretKey;

  KeyPairResult({required this.publicKey, required this.secretKey});
}

/// AsymBundleResult holds X25519 + Ed25519 key pairs.
class AsymBundleResult {
  final Uint8List boxPublic;
  final Uint8List boxSecret;
  final Uint8List signPublic;
  final Uint8List signSecret;

  AsymBundleResult({
    required this.boxPublic,
    required this.boxSecret,
    required this.signPublic,
    required this.signSecret,
  });
}

// =============================================================================
// Main wrapper class
// =============================================================================

/// Idiomatic Dart wrapper around the CryptoLib C FFI bridge.
class CryptoLib {
  final DynamicLibrary _lib;

  // -- Cached function lookups --
  late final _InitDart _init;
  late final _VersionDart _version;
  late final _RandomBytesDart _randomBytes;
  late final _SecureEqualDart _secureEqual;

  // Memory free
  late final _BufferFreeDart _bufferFree;
  late final _StrFreeDart _strFree;
  late final _KeyPairFreeDart _keypairFree;
  late final _BundleFreeDart _bundleFree;
  late final _PacketFreeDart _packetFree;
  late final _DerivedKeysFreeDart _derivedKeysFree;
  late final _EntropyInfoFreeDart _entropyInfoFree;

  // Hashing
  late final _Blake2bDart _blake2b;
  late final _Sha256Dart _sha256;
  late final _Sha512Dart _sha512;
  late final _Blake3Dart _blake3;
  late final _Blake3KeyedDart _blake3Keyed;
  late final _Blake3DeriveKeyDart _blake3DeriveKey;
  late final _HmacSha512Dart _hmacSha512;
  late final _HmacSha512VerifyDart _hmacSha512Verify;

  // Argon2id
  late final _Argon2idHashStrDart _argon2idHashStr;
  late final _Argon2idVerifyStrDart _argon2idVerifyStr;
  late final _Argon2idDeriveDart _argon2idDerive;

  // Symmetric
  late final _SymKeygenDart _symKeygen;
  late final _XChaCha20EncDart _xchacha20Enc;
  late final _XChaCha20DecDart _xchacha20Dec;
  late final _Aes256GcmEncDart _aes256gcmEnc;
  late final _Aes256GcmDecDart _aes256gcmDec;
  late final _Aes256GcmAvailableDart _aes256gcmAvailable;

  // SecretStream
  late final _StreamEncCreateDart _streamEncCreate;
  late final _StreamEncHeaderDart _streamEncHeader;
  late final _StreamEncPushDart _streamEncPush;
  late final _StreamEncFreeDart _streamEncFree;
  late final _StreamDecCreateDart _streamDecCreate;
  late final _StreamDecPullDart _streamDecPull;
  late final _StreamDecFreeDart _streamDecFree;

  // Ed25519
  late final _Ed25519KeygenDart _ed25519Keygen;
  late final _Ed25519KeygenFromSeedDart _ed25519KeygenFromSeed;
  late final _Ed25519SignDart _ed25519Sign;
  late final _Ed25519VerifyDart _ed25519Verify;

  // X25519
  late final _X25519KeygenDart _x25519Keygen;
  late final _X25519SharedSecretDart _x25519SharedSecret;

  // Box
  late final _BoxKeygenDart _boxKeygen;
  late final _BoxEncryptDart _boxEncrypt;
  late final _BoxDecryptDart _boxDecrypt;

  // SealedBox
  late final _SealedBoxEncryptDart _sealedboxEncrypt;
  late final _SealedBoxDecryptDart _sealedboxDecrypt;

  // Vault
  late final _VaultCreateDart _vaultCreate;
  late final _VaultFromEntropyDart _vaultFromEntropy;
  late final _VaultSealDart _vaultSeal;
  late final _VaultSealBoostedDart _vaultSealBoosted;
  late final _VaultOpenDart _vaultOpen;
  late final _VaultOpenBoostedDart _vaultOpenBoosted;
  late final _VaultPublicKeyDart _vaultPublicKey;
  late final _PacketSerialiseDart _packetSerialise;
  late final _PacketDeserialiseDart _packetDeserialise;
  late final _VaultFreeDart _vaultFree;

  // Asymmetric vault
  late final _AsymBundleGenerateDart _asymBundleGenerate;
  late final _AsymVaultSealDart _asymVaultSeal;
  late final _AsymVaultOpenDart _asymVaultOpen;

  // Entropy
  late final _EntropyFromFileDart _entropyFromFile;
  late final _EntropyFromFileDart _entropyFromFileDet;
  late final _EntropyFromFilesDart _entropyFromFiles;
  late final _EntropyFromFilesDart _entropyFromFilesDet;
  late final _EntropyDeriveAllDart _entropyDeriveAll;
  late final _EntropySymKeyDart _entropySymKey;
  late final _EntropyRawDart _entropyRaw;
  late final _EntropyBoostDart _entropyBoost;
  late final _EntropyInfoDart _entropyInfo;
  late final _EntropyAsymBundleDart _entropyAsymBundle;
  late final _EntropyRefreshDart _entropyRefresh;
  late final _EntropyFreeDart _entropyFree;

  // Entropy convenience
  late final _KeyFromFileDart _keyFromFile;
  late final _SealFromFileDart _sealFromFile;
  late final _OpenFromFileDart _openFromFile;

  // Steganography
  late final _StegoEmbedDart _stegoEmbed;
  late final _StegoExtractDart _stegoExtract;
  late final _StegoCapacityDart _stegoCapacity;

  CryptoLib._(this._lib) {
    // Init & version
    _init = _lib.lookupFunction<_InitC, _InitDart>('cryptolib_init');
    _version = _lib.lookupFunction<_VersionC, _VersionDart>('cryptolib_version');
    _randomBytes = _lib.lookupFunction<_RandomBytesC, _RandomBytesDart>('cryptolib_random_bytes');
    _secureEqual = _lib.lookupFunction<_SecureEqualC, _SecureEqualDart>('cryptolib_secure_equal');

    // Memory free
    _bufferFree = _lib.lookupFunction<_BufferFreeC, _BufferFreeDart>('cryptolib_buffer_free');
    _strFree = _lib.lookupFunction<_StrFreeC, _StrFreeDart>('cryptolib_str_free');
    _keypairFree = _lib.lookupFunction<_KeyPairFreeC, _KeyPairFreeDart>('cryptolib_keypair_free');
    _bundleFree = _lib.lookupFunction<_BundleFreeC, _BundleFreeDart>('cryptolib_bundle_free');
    _packetFree = _lib.lookupFunction<_PacketFreeC, _PacketFreeDart>('cryptolib_packet_free');
    _derivedKeysFree = _lib.lookupFunction<_DerivedKeysFreeC, _DerivedKeysFreeDart>('cryptolib_derived_keys_free');
    _entropyInfoFree = _lib.lookupFunction<_EntropyInfoFreeC, _EntropyInfoFreeDart>('cryptolib_entropy_info_free');

    // Hashing
    _blake2b = _lib.lookupFunction<_Blake2bC, _Blake2bDart>('cryptolib_blake2b');
    _sha256 = _lib.lookupFunction<_Sha256C, _Sha256Dart>('cryptolib_sha256');
    _sha512 = _lib.lookupFunction<_Sha512C, _Sha512Dart>('cryptolib_sha512');
    _blake3 = _lib.lookupFunction<_Blake3C, _Blake3Dart>('cryptolib_blake3');
    _blake3Keyed = _lib.lookupFunction<_Blake3KeyedC, _Blake3KeyedDart>('cryptolib_blake3_keyed');
    _blake3DeriveKey = _lib.lookupFunction<_Blake3DeriveKeyC, _Blake3DeriveKeyDart>('cryptolib_blake3_derive_key');
    _hmacSha512 = _lib.lookupFunction<_HmacSha512C, _HmacSha512Dart>('cryptolib_hmac_sha512');
    _hmacSha512Verify = _lib.lookupFunction<_HmacSha512VerifyC, _HmacSha512VerifyDart>('cryptolib_hmac_sha512_verify');

    // Argon2id
    _argon2idHashStr = _lib.lookupFunction<_Argon2idHashStrC, _Argon2idHashStrDart>('cryptolib_argon2id_hash_str');
    _argon2idVerifyStr = _lib.lookupFunction<_Argon2idVerifyStrC, _Argon2idVerifyStrDart>('cryptolib_argon2id_verify_str');
    _argon2idDerive = _lib.lookupFunction<_Argon2idDeriveC, _Argon2idDeriveDart>('cryptolib_argon2id_derive');

    // Symmetric
    _symKeygen = _lib.lookupFunction<_SymKeygenC, _SymKeygenDart>('cryptolib_sym_keygen');
    _xchacha20Enc = _lib.lookupFunction<_XChaCha20EncC, _XChaCha20EncDart>('cryptolib_xchacha20_encrypt');
    _xchacha20Dec = _lib.lookupFunction<_XChaCha20DecC, _XChaCha20DecDart>('cryptolib_xchacha20_decrypt');
    _aes256gcmEnc = _lib.lookupFunction<_Aes256GcmEncC, _Aes256GcmEncDart>('cryptolib_aes256gcm_encrypt');
    _aes256gcmDec = _lib.lookupFunction<_Aes256GcmDecC, _Aes256GcmDecDart>('cryptolib_aes256gcm_decrypt');
    _aes256gcmAvailable = _lib.lookupFunction<_Aes256GcmAvailableC, _Aes256GcmAvailableDart>('cryptolib_aes256gcm_available');

    // SecretStream
    _streamEncCreate = _lib.lookupFunction<_StreamEncCreateC, _StreamEncCreateDart>('cryptolib_stream_enc_create');
    _streamEncHeader = _lib.lookupFunction<_StreamEncHeaderC, _StreamEncHeaderDart>('cryptolib_stream_enc_header');
    _streamEncPush = _lib.lookupFunction<_StreamEncPushC, _StreamEncPushDart>('cryptolib_stream_enc_push');
    _streamEncFree = _lib.lookupFunction<_StreamEncFreeC, _StreamEncFreeDart>('cryptolib_stream_enc_free');
    _streamDecCreate = _lib.lookupFunction<_StreamDecCreateC, _StreamDecCreateDart>('cryptolib_stream_dec_create');
    _streamDecPull = _lib.lookupFunction<_StreamDecPullC, _StreamDecPullDart>('cryptolib_stream_dec_pull');
    _streamDecFree = _lib.lookupFunction<_StreamDecFreeC, _StreamDecFreeDart>('cryptolib_stream_dec_free');

    // Ed25519
    _ed25519Keygen = _lib.lookupFunction<_Ed25519KeygenC, _Ed25519KeygenDart>('cryptolib_ed25519_keygen');
    _ed25519KeygenFromSeed = _lib.lookupFunction<_Ed25519KeygenFromSeedC, _Ed25519KeygenFromSeedDart>('cryptolib_ed25519_keygen_from_seed');
    _ed25519Sign = _lib.lookupFunction<_Ed25519SignC, _Ed25519SignDart>('cryptolib_ed25519_sign');
    _ed25519Verify = _lib.lookupFunction<_Ed25519VerifyC, _Ed25519VerifyDart>('cryptolib_ed25519_verify');

    // X25519
    _x25519Keygen = _lib.lookupFunction<_X25519KeygenC, _X25519KeygenDart>('cryptolib_x25519_keygen');
    _x25519SharedSecret = _lib.lookupFunction<_X25519SharedSecretC, _X25519SharedSecretDart>('cryptolib_x25519_shared_secret');

    // Box
    _boxKeygen = _lib.lookupFunction<_BoxKeygenC, _BoxKeygenDart>('cryptolib_box_keygen');
    _boxEncrypt = _lib.lookupFunction<_BoxEncryptC, _BoxEncryptDart>('cryptolib_box_encrypt');
    _boxDecrypt = _lib.lookupFunction<_BoxDecryptC, _BoxDecryptDart>('cryptolib_box_decrypt');

    // SealedBox
    _sealedboxEncrypt = _lib.lookupFunction<_SealedBoxEncryptC, _SealedBoxEncryptDart>('cryptolib_sealedbox_encrypt');
    _sealedboxDecrypt = _lib.lookupFunction<_SealedBoxDecryptC, _SealedBoxDecryptDart>('cryptolib_sealedbox_decrypt');

    // Vault
    _vaultCreate = _lib.lookupFunction<_VaultCreateC, _VaultCreateDart>('cryptolib_vault_create');
    _vaultFromEntropy = _lib.lookupFunction<_VaultFromEntropyC, _VaultFromEntropyDart>('cryptolib_vault_from_entropy');
    _vaultSeal = _lib.lookupFunction<_VaultSealC, _VaultSealDart>('cryptolib_vault_seal');
    _vaultSealBoosted = _lib.lookupFunction<_VaultSealBoostedC, _VaultSealBoostedDart>('cryptolib_vault_seal_boosted');
    _vaultOpen = _lib.lookupFunction<_VaultOpenC, _VaultOpenDart>('cryptolib_vault_open');
    _vaultOpenBoosted = _lib.lookupFunction<_VaultOpenBoostedC, _VaultOpenBoostedDart>('cryptolib_vault_open_boosted');
    _vaultPublicKey = _lib.lookupFunction<_VaultPublicKeyC, _VaultPublicKeyDart>('cryptolib_vault_public_key');
    _packetSerialise = _lib.lookupFunction<_PacketSerialiseC, _PacketSerialiseDart>('cryptolib_packet_serialise');
    _packetDeserialise = _lib.lookupFunction<_PacketDeserialiseC, _PacketDeserialiseDart>('cryptolib_packet_deserialise');
    _vaultFree = _lib.lookupFunction<_VaultFreeC, _VaultFreeDart>('cryptolib_vault_free');

    // Asymmetric vault
    _asymBundleGenerate = _lib.lookupFunction<_AsymBundleGenerateC, _AsymBundleGenerateDart>('cryptolib_asym_bundle_generate');
    _asymVaultSeal = _lib.lookupFunction<_AsymVaultSealC, _AsymVaultSealDart>('cryptolib_asym_vault_seal');
    _asymVaultOpen = _lib.lookupFunction<_AsymVaultOpenC, _AsymVaultOpenDart>('cryptolib_asym_vault_open');

    // Entropy
    _entropyFromFile = _lib.lookupFunction<_EntropyFromFileC, _EntropyFromFileDart>('cryptolib_entropy_from_file');
    _entropyFromFileDet = _lib.lookupFunction<_EntropyFromFileC, _EntropyFromFileDart>('cryptolib_entropy_from_file_deterministic');
    _entropyFromFiles = _lib.lookupFunction<_EntropyFromFilesC, _EntropyFromFilesDart>('cryptolib_entropy_from_files');
    _entropyFromFilesDet = _lib.lookupFunction<_EntropyFromFilesC, _EntropyFromFilesDart>('cryptolib_entropy_from_files_deterministic');
    _entropyDeriveAll = _lib.lookupFunction<_EntropyDeriveAllC, _EntropyDeriveAllDart>('cryptolib_entropy_derive_all');
    _entropySymKey = _lib.lookupFunction<_EntropySymKeyC, _EntropySymKeyDart>('cryptolib_entropy_symmetric_key');
    _entropyRaw = _lib.lookupFunction<_EntropyRawC, _EntropyRawDart>('cryptolib_entropy_raw');
    _entropyBoost = _lib.lookupFunction<_EntropyBoostC, _EntropyBoostDart>('cryptolib_entropy_boost');
    _entropyInfo = _lib.lookupFunction<_EntropyInfoC, _EntropyInfoDart>('cryptolib_entropy_info');
    _entropyAsymBundle = _lib.lookupFunction<_EntropyAsymBundleC, _EntropyAsymBundleDart>('cryptolib_entropy_asym_bundle');
    _entropyRefresh = _lib.lookupFunction<_EntropyRefreshC, _EntropyRefreshDart>('cryptolib_entropy_refresh');
    _entropyFree = _lib.lookupFunction<_EntropyFreeC, _EntropyFreeDart>('cryptolib_entropy_free');

    // Entropy convenience
    _keyFromFile = _lib.lookupFunction<_KeyFromFileC, _KeyFromFileDart>('cryptolib_key_from_file');
    _sealFromFile = _lib.lookupFunction<_SealFromFileC, _SealFromFileDart>('cryptolib_seal_from_file');
    _openFromFile = _lib.lookupFunction<_OpenFromFileC, _OpenFromFileDart>('cryptolib_open_from_file');

    // Steganography
    _stegoEmbed = _lib.lookupFunction<_StegoEmbedC, _StegoEmbedDart>('cryptolib_stego_embed');
    _stegoExtract = _lib.lookupFunction<_StegoExtractC, _StegoExtractDart>('cryptolib_stego_extract');
    _stegoCapacity = _lib.lookupFunction<_StegoCapacityC, _StegoCapacityDart>('cryptolib_stego_capacity');
  }

  /// Load the shared library from a path.
  factory CryptoLib.load([String? path]) {
    final lib = path != null
        ? DynamicLibrary.open(path)
        : DynamicLibrary.process();
    return CryptoLib._(lib);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  Uint8List _copyBuf(CryptoBuffer buf) {
    if (buf.data == nullptr || buf.len == 0) return Uint8List(0);
    final out = Uint8List(buf.len);
    out.setAll(0, buf.data.asTypedList(buf.len));
    final ptr = calloc<CryptoBuffer>();
    ptr.ref.data = buf.data;
    ptr.ref.len = buf.len;
    _bufferFree(ptr);
    calloc.free(ptr);
    return out;
  }

  /// Copy a CryptoBuffer's bytes out WITHOUT freeing it (caller frees the
  /// owning native struct separately, e.g. via cryptolib_kem_encaps_free).
  Uint8List _copyBufView(CryptoBuffer buf) {
    if (buf.data == nullptr || buf.len == 0) return Uint8List(0);
    final out = Uint8List(buf.len);
    out.setAll(0, buf.data.asTypedList(buf.len));
    return out;
  }

  /// Copy both buffers out of a KEM encapsulation result, then release the
  /// whole result with cryptolib_kem_encaps_free in a single call.
  (Uint8List, Uint8List) _drainKemEncaps(CryptoKemEncapsResult r) {
    final ct = _copyBufView(r.ciphertext);
    final ss = _copyBufView(r.sharedSecret);
    final rp = calloc<CryptoKemEncapsResult>();
    rp.ref.ciphertext.data = r.ciphertext.data;
    rp.ref.ciphertext.len = r.ciphertext.len;
    rp.ref.sharedSecret.data = r.sharedSecret.data;
    rp.ref.sharedSecret.len = r.sharedSecret.len;
    _lib.lookupFunction<Void Function(Pointer<CryptoKemEncapsResult>),
            void Function(Pointer<CryptoKemEncapsResult>)>(
        'cryptolib_kem_encaps_free')(rp);
    calloc.free(rp);
    return (ct, ss);
  }

  Uint8List _checkBufResult(CryptoBufferResult r) {
    if (r.error != nullptr) {
      final msg = r.error.toDartString();
      _strFree(r.error);
      throw Exception(msg);
    }
    return _copyBuf(r.buf);
  }

  void _checkResult(CryptoResult r) {
    if (r.ok != 1) {
      final msg = r.error != nullptr ? r.error.toDartString() : 'Unknown error';
      if (r.error != nullptr) _strFree(r.error);
      throw Exception(msg);
    }
    if (r.error != nullptr) _strFree(r.error);
  }

  Pointer<Uint8> _toNative(Uint8List data) {
    if (data.isEmpty) return nullptr;
    final ptr = calloc<Uint8>(data.length);
    ptr.asTypedList(data.length).setAll(0, data);
    return ptr;
  }

  /// Marshal a list of byte buffers into the C `const uint8_t* const*` +
  /// `const size_t*` array pair. Returns the pointer-array and length-array;
  /// release both (and the element buffers) with [_freeNativeList].
  (Pointer<Pointer<Uint8>>, Pointer<Size>) _toNativeList(List<Uint8List> items) {
    final n = items.length;
    final ptrs = calloc<Pointer<Uint8>>(n);
    final lens = calloc<Size>(n);
    for (var i = 0; i < n; i++) {
      final b = items[i];
      // calloc(0) is implementation-defined; allocate at least 1 byte so every
      // element pointer is non-null and distinct.
      final p = calloc<Uint8>(b.isEmpty ? 1 : b.length);
      if (b.isNotEmpty) p.asTypedList(b.length).setAll(0, b);
      ptrs[i] = p;
      lens[i] = b.length;
    }
    return (ptrs, lens);
  }

  void _freeNativeList(Pointer<Pointer<Uint8>> ptrs, Pointer<Size> lens, int n) {
    for (var i = 0; i < n; i++) {
      if (ptrs[i] != nullptr) calloc.free(ptrs[i]);
    }
    calloc.free(ptrs);
    calloc.free(lens);
  }

  Packet _extractPacket(CryptoPacket cp, Pointer<Pointer<Utf8>> errPtr) {
    if (errPtr.value != nullptr) {
      final msg = errPtr.value.toDartString();
      _strFree(errPtr.value);
      throw Exception(msg);
    }
    return Packet(
      ciphertext: _copyBuf(cp.ciphertext),
      signature: _copyBuf(cp.signature),
      kdfSalt: _copyBuf(cp.kdfSalt),
    );
  }

  Pointer<CryptoPacket> _packetToNative(Packet pkt) {
    final cpkt = calloc<CryptoPacket>();
    final ct = _toNative(pkt.ciphertext);
    final sig = _toNative(pkt.signature);
    final salt = _toNative(pkt.kdfSalt);
    cpkt.ref.ciphertext.data = ct;
    cpkt.ref.ciphertext.len = pkt.ciphertext.length;
    cpkt.ref.signature.data = sig;
    cpkt.ref.signature.len = pkt.signature.length;
    cpkt.ref.kdfSalt.data = salt;
    cpkt.ref.kdfSalt.len = pkt.kdfSalt.length;
    return cpkt;
  }

  void _freePacketNative(Pointer<CryptoPacket> cpkt) {
    if (cpkt.ref.ciphertext.data != nullptr) calloc.free(cpkt.ref.ciphertext.data);
    if (cpkt.ref.signature.data != nullptr) calloc.free(cpkt.ref.signature.data);
    if (cpkt.ref.kdfSalt.data != nullptr) calloc.free(cpkt.ref.kdfSalt.data);
    calloc.free(cpkt);
  }

  KeyPairResult _extractKeyPair(CryptoKeyPair kp) {
    return KeyPairResult(
      publicKey: _copyBuf(kp.publicKey),
      secretKey: _copyBuf(kp.secretKey),
    );
  }

  AsymBundleResult _extractBundle(CryptoAsymBundle ab) {
    return AsymBundleResult(
      boxPublic: _copyBuf(ab.boxPublic),
      boxSecret: _copyBuf(ab.boxSecret),
      signPublic: _copyBuf(ab.signPublic),
      signSecret: _copyBuf(ab.signSecret),
    );
  }

  // ── Init & version ────────────────────────────────────────────────────────

  /// Initialise libsodium. Call once at app start.
  void init() {
    if (_init() != 0) throw Exception('cryptolib: init failed');
  }

  /// Get the library version string.
  String version() => _version().toDartString();

  // ── Random bytes ──────────────────────────────────────────────────────────

  /// Generate n cryptographically secure random bytes.
  Uint8List randomBytes(int n) => _checkBufResult(_randomBytes(n));

  // ── Secure equal ──────────────────────────────────────────────────────────

  /// Constant-time comparison. Returns true if equal.
  bool secureEqual(Uint8List a, Uint8List b) {
    final pa = _toNative(a);
    final pb = _toNative(b);
    try {
      return _secureEqual(pa, a.length, pb, b.length) == 1;
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
    }
  }

  // ── Hashing ───────────────────────────────────────────────────────────────

  /// BLAKE2b-512 hash. key may be empty for unkeyed.
  Uint8List blake2b(Uint8List msg, [Uint8List? key]) {
    final pm = _toNative(msg);
    Pointer<Uint8> pk = nullptr;
    int kl = 0;
    if (key != null && key.isNotEmpty) {
      pk = _toNative(key);
      kl = key.length;
    }
    try {
      return _checkBufResult(_blake2b(pm, msg.length, pk, kl));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// SHA-256 hash.
  Uint8List sha256(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_sha256(pm, msg.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
    }
  }

  /// SHA-512 hash.
  Uint8List sha512(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_sha512(pm, msg.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
    }
  }

  /// BLAKE3 hash. [outLen] is the extendable output length in bytes
  /// (defaults to 32). Pass a larger value to use BLAKE3 as an XOF.
  Uint8List blake3(Uint8List msg, {int outLen = 32}) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_blake3(pm, msg.length, outLen));
    } finally {
      if (pm != nullptr) calloc.free(pm);
    }
  }

  /// BLAKE3 keyed MAC. [key] must be exactly 32 bytes. [outLen] defaults to 32.
  Uint8List blake3Keyed(Uint8List msg, Uint8List key, {int outLen = 32}) {
    if (key.length != 32) {
      throw ArgumentError('BLAKE3 keyed MAC requires a 32-byte key, got ${key.length}');
    }
    final pm = _toNative(msg);
    final pk = _toNative(key);
    try {
      return _checkBufResult(_blake3Keyed(pm, msg.length, pk, key.length, outLen));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// BLAKE3 key derivation. [context] is a hard-coded, application-unique
  /// domain-separation string; [ikm] is the input key material. [outLen]
  /// defaults to 32.
  Uint8List blake3DeriveKey(String context, Uint8List ikm, {int outLen = 32}) {
    final cc = context.toNativeUtf8();
    final pk = _toNative(ikm);
    try {
      return _checkBufResult(_blake3DeriveKey(cc, pk, ikm.length, outLen));
    } finally {
      calloc.free(cc);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HMAC-SHA256. [key] should be >= 32 bytes. Returns a 32-byte tag.
  Uint8List hmacSha256(Uint8List msg, Uint8List key) {
    final pm = _toNative(msg), pk = _toNative(key);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hmac_sha256')(pm, msg.length, pk, key.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Verify an HMAC-SHA256 tag in constant time. Returns true if valid.
  bool hmacSha256Verify(Uint8List msg, Uint8List mac, Uint8List key) {
    final pm = _toNative(msg), pmac = _toNative(mac), pk = _toNative(key);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hmac_sha256_verify')(
              pm, msg.length, pmac, mac.length, pk, key.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pmac != nullptr) calloc.free(pmac);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HKDF-SHA256 extract: PRK = HMAC(salt, IKM). Pass an empty [salt] for the
  /// all-zero default. Returns a 32-byte pseudorandom key.
  Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) {
    final ps = (salt != null && salt.isNotEmpty) ? _toNative(salt) : nullptr;
    final pk = _toNative(ikm);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hkdf_extract')(ps, salt?.length ?? 0, pk, ikm.length));
    } finally {
      if (ps != nullptr) calloc.free(ps);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HKDF-SHA256 expand: derive [outLen] bytes of output key material from a
  /// pseudorandom key [prk] and optional [info] context.
  Uint8List hkdfExpand(Uint8List prk, {Uint8List? info, int outLen = 32}) {
    final pp = _toNative(prk);
    final pi = (info != null && info.isNotEmpty) ? _toNative(info) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_hkdf_expand')(pp, prk.length, pi, info?.length ?? 0, outLen));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pi != nullptr) calloc.free(pi);
    }
  }

  /// HKDF-SHA256 one-shot (extract + expand): derive [outLen] bytes from [ikm]
  /// with optional [salt] and [info].
  Uint8List hkdfDerive(Uint8List ikm,
      {Uint8List? salt, Uint8List? info, int outLen = 32}) {
    final pk = _toNative(ikm);
    final ps = (salt != null && salt.isNotEmpty) ? _toNative(salt) : nullptr;
    final pi = (info != null && info.isNotEmpty) ? _toNative(info) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_hkdf_derive')(
              pk, ikm.length, ps, salt?.length ?? 0, pi, info?.length ?? 0, outLen));
    } finally {
      if (pk != nullptr) calloc.free(pk);
      if (ps != nullptr) calloc.free(ps);
      if (pi != nullptr) calloc.free(pi);
    }
  }

  /// HMAC-SHA512.
  Uint8List hmacSha512(Uint8List msg, Uint8List key) {
    final pm = _toNative(msg);
    final pk = _toNative(key);
    try {
      return _checkBufResult(_hmacSha512(pm, msg.length, pk, key.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HMAC-SHA512 verify. Returns true if valid.
  bool hmacSha512Verify(Uint8List msg, Uint8List mac, Uint8List key) {
    final pm = _toNative(msg);
    final pmac = _toNative(mac);
    final pk = _toNative(key);
    try {
      return _hmacSha512Verify(pm, msg.length, pmac, mac.length, pk, key.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pmac != nullptr) calloc.free(pmac);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  // ── Argon2id ──────────────────────────────────────────────────────────────

  /// Hash a password to PHC string format.
  Uint8List argon2idHashStr(String password, {int ops = 2, int mem = 67108864}) {
    final cp = password.toNativeUtf8();
    try {
      return _checkBufResult(_argon2idHashStr(cp, ops, mem));
    } finally {
      calloc.free(cp);
    }
  }

  /// Verify password against PHC string. Returns true if correct.
  bool argon2idVerifyStr(String password, String phcStr) {
    final cp = password.toNativeUtf8();
    final cphc = phcStr.toNativeUtf8();
    try {
      return _argon2idVerifyStr(cp, cphc) == 1;
    } finally {
      calloc.free(cp);
      calloc.free(cphc);
    }
  }

  /// Derive a key from password + salt.
  Uint8List argon2idDerive(String password, Uint8List salt,
      {int keyLen = 32, int ops = 2, int mem = 67108864}) {
    final cp = password.toNativeUtf8();
    final ps = _toNative(salt);
    try {
      return _checkBufResult(_argon2idDerive(cp, ps, salt.length, keyLen, ops, mem));
    } finally {
      calloc.free(cp);
      if (ps != nullptr) calloc.free(ps);
    }
  }

  // ── Symmetric encryption ─────────────────────────────────────────────────

  /// Generate a 32-byte random symmetric key.
  Uint8List symKeygen() => _checkBufResult(_symKeygen());

  /// XChaCha20-Poly1305 encrypt.
  Uint8List xchacha20Encrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) {
    final pp = _toNative(plaintext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_xchacha20Enc(pp, plaintext.length, pk, key.length, pa, al));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// XChaCha20-Poly1305 decrypt.
  Uint8List xchacha20Decrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) {
    final pc = _toNative(ciphertext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_xchacha20Dec(pc, ciphertext.length, pk, key.length, pa, al));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// AES-256-GCM encrypt.
  Uint8List aes256gcmEncrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) {
    final pp = _toNative(plaintext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_aes256gcmEnc(pp, plaintext.length, pk, key.length, pa, al));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// AES-256-GCM decrypt.
  Uint8List aes256gcmDecrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) {
    final pc = _toNative(ciphertext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_aes256gcmDec(pc, ciphertext.length, pk, key.length, pa, al));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Check if AES-256-GCM is available on this CPU.
  bool aes256gcmAvailable() => _aes256gcmAvailable() != 0;

  // ── Committing AEAD (UtC: key-committing XChaCha20-Poly1305) ───────────────

  /// Committing AEAD encrypt. Unlike a plain AEAD, the ciphertext binds the
  /// exact key, so it cannot be opened under a second key (no invisible
  /// salamander / partitioning-oracle attack). [key] is 32 bytes.
  Uint8List committingEncrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) {
    final pp = _toNative(plaintext), pk = _toNative(key);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_committing_encrypt')(
              pp, plaintext.length, pk, key.length, pa, aad?.length ?? 0));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Committing AEAD decrypt. Throws if the key/AAD don't match or the
  /// commitment check fails. [key] is 32 bytes.
  Uint8List committingDecrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) {
    final pc = _toNative(ciphertext), pk = _toNative(key);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_committing_decrypt')(
              pc, ciphertext.length, pk, key.length, pa, aad?.length ?? 0));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  // ── SecretStream ──────────────────────────────────────────────────────────

  /// Streaming encrypt: encrypt chunks of data with ordering.
  /// Returns (header, encryptedChunks).
  (Uint8List header, List<Uint8List> chunks) streamEncrypt(Uint8List key, List<Uint8List> plaintextChunks) {
    final pk = _toNative(key);
    final handle = _streamEncCreate(pk);
    calloc.free(pk);
    if (handle == nullptr) throw Exception('streamEncCreate failed');

    try {
      final headerResult = _streamEncHeader(handle);
      final header = _checkBufResult(headerResult);

      final encChunks = <Uint8List>[];
      for (int i = 0; i < plaintextChunks.length; i++) {
        final isLast = i == plaintextChunks.length - 1;
        final tag = isLast ? 3 : 0; // FINAL=3, MESSAGE=0
        final pp = _toNative(plaintextChunks[i]);
        try {
          final result = _streamEncPush(handle, pp, plaintextChunks[i].length, tag);
          encChunks.add(_checkBufResult(result));
        } finally {
          if (pp != nullptr) calloc.free(pp);
        }
      }
      return (header, encChunks);
    } finally {
      _streamEncFree(handle);
    }
  }

  /// Streaming decrypt: decrypt chunks of data.
  List<Uint8List> streamDecrypt(Uint8List key, Uint8List header, List<Uint8List> ciphertextChunks) {
    final pk = _toNative(key);
    final ph = _toNative(header);
    final handle = _streamDecCreate(pk, ph);
    calloc.free(pk);
    calloc.free(ph);
    if (handle == nullptr) throw Exception('streamDecCreate failed');

    try {
      final decChunks = <Uint8List>[];
      final outTag = calloc<Uint8>();
      for (final chunk in ciphertextChunks) {
        final pc = _toNative(chunk);
        try {
          final result = _streamDecPull(handle, pc, chunk.length, outTag);
          decChunks.add(_checkBufResult(result));
        } finally {
          if (pc != nullptr) calloc.free(pc);
        }
      }
      calloc.free(outTag);
      return decChunks;
    } finally {
      _streamDecFree(handle);
    }
  }

  // ── Ed25519 ───────────────────────────────────────────────────────────────

  /// Generate an Ed25519 signing keypair.
  KeyPairResult ed25519Keygen() => _extractKeyPair(_ed25519Keygen());

  /// Generate Ed25519 keypair from a 32-byte seed (deterministic).
  KeyPairResult ed25519KeygenFromSeed(Uint8List seed) {
    final ps = _toNative(seed);
    try {
      return _extractKeyPair(_ed25519KeygenFromSeed(ps, seed.length));
    } finally {
      if (ps != nullptr) calloc.free(ps);
    }
  }

  /// Sign a message. Returns 64-byte detached signature.
  Uint8List ed25519Sign(Uint8List msg, Uint8List secretKey) {
    final pm = _toNative(msg);
    final pk = _toNative(secretKey);
    try {
      return _checkBufResult(_ed25519Sign(pm, msg.length, pk, secretKey.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Verify a detached signature. Returns true if valid.
  bool ed25519Verify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final pm = _toNative(msg);
    final ps = _toNative(sig);
    final pk = _toNative(publicKey);
    try {
      return _ed25519Verify(pm, msg.length, ps, sig.length, pk, publicKey.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (ps != nullptr) calloc.free(ps);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  // ── X25519 ────────────────────────────────────────────────────────────────

  /// Generate an X25519 key agreement keypair.
  KeyPairResult x25519Keygen() => _extractKeyPair(_x25519Keygen());

  /// Compute X25519 shared secret (32 bytes).
  Uint8List x25519SharedSecret(Uint8List ourSecret, Uint8List theirPublic) {
    final pos = _toNative(ourSecret);
    final ptp = _toNative(theirPublic);
    try {
      return _checkBufResult(_x25519SharedSecret(pos, ourSecret.length, ptp, theirPublic.length));
    } finally {
      if (pos != nullptr) calloc.free(pos);
      if (ptp != nullptr) calloc.free(ptp);
    }
  }

  // ── Box ───────────────────────────────────────────────────────────────────

  /// Generate a Box keypair (X25519).
  KeyPairResult boxKeygen() => _extractKeyPair(_boxKeygen());

  /// Box encrypt: sender to recipient authenticated encryption.
  Uint8List boxEncrypt(Uint8List plaintext, Uint8List recipientPub, Uint8List senderSec) {
    final pp = _toNative(plaintext);
    final prp = _toNative(recipientPub);
    final pss = _toNative(senderSec);
    try {
      return _checkBufResult(_boxEncrypt(pp, plaintext.length, prp, recipientPub.length, pss, senderSec.length));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (prp != nullptr) calloc.free(prp);
      if (pss != nullptr) calloc.free(pss);
    }
  }

  /// Box decrypt.
  Uint8List boxDecrypt(Uint8List ciphertext, Uint8List senderPub, Uint8List recipientSec) {
    final pc = _toNative(ciphertext);
    final psp = _toNative(senderPub);
    final prs = _toNative(recipientSec);
    try {
      return _checkBufResult(_boxDecrypt(pc, ciphertext.length, psp, senderPub.length, prs, recipientSec.length));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (psp != nullptr) calloc.free(psp);
      if (prs != nullptr) calloc.free(prs);
    }
  }

  // ── SealedBox ─────────────────────────────────────────────────────────────

  /// SealedBox encrypt (anonymous sender).
  Uint8List sealedboxEncrypt(Uint8List plaintext, Uint8List recipientPub) {
    final pp = _toNative(plaintext);
    final prp = _toNative(recipientPub);
    try {
      return _checkBufResult(_sealedboxEncrypt(pp, plaintext.length, prp, recipientPub.length));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (prp != nullptr) calloc.free(prp);
    }
  }

  /// SealedBox decrypt.
  Uint8List sealedboxDecrypt(Uint8List ciphertext, Uint8List recipientPub, Uint8List recipientSec) {
    final pc = _toNative(ciphertext);
    final prp = _toNative(recipientPub);
    final prs = _toNative(recipientSec);
    try {
      return _checkBufResult(_sealedboxDecrypt(pc, ciphertext.length, prp, recipientPub.length, prs, recipientSec.length));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (prp != nullptr) calloc.free(prp);
      if (prs != nullptr) calloc.free(prs);
    }
  }

  // ── Vault ─────────────────────────────────────────────────────────────────

  /// Create a vault from a 32-byte master key.
  Pointer<Void> vaultCreate(Uint8List masterKey, {int kdfPreset = 0}) {
    final pk = _toNative(masterKey);
    try {
      final h = _vaultCreate(pk, masterKey.length, kdfPreset);
      if (h == nullptr) throw Exception('cryptolib: vault create failed');
      return h;
    } finally {
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Create a vault from an entropy handle.
  Pointer<Void> vaultFromEntropy(Pointer<Void> entropy, {int kdf = 0}) {
    final h = _vaultFromEntropy(entropy, kdf);
    if (h == nullptr) throw Exception('cryptolib: vault from entropy failed');
    return h;
  }

  /// Seal plaintext through the vault pipeline.
  Packet vaultSeal(Pointer<Void> vault, Uint8List plaintext, String aad) {
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vaultSeal(vault, pp, plaintext.length, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Seal with entropy boost (two-factor).
  Packet vaultSealBoosted(Pointer<Void> vault, Uint8List plaintext, String aad, Pointer<Void> boost) {
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vaultSealBoosted(vault, pp, plaintext.length, caad, boost, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Open a vault packet.
  Uint8List vaultOpen(Pointer<Void> vault, Packet pkt, String aad) {
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vaultOpen(vault, cpkt, caad));
    } finally {
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

  /// Open with entropy boost.
  Uint8List vaultOpenBoosted(Pointer<Void> vault, Packet pkt, String aad, Pointer<Void> boost) {
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vaultOpenBoosted(vault, cpkt, caad, boost));
    } finally {
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

  /// Get the vault's Ed25519 public key.
  Uint8List vaultPublicKey(Pointer<Void> vault) {
    return _checkBufResult(_vaultPublicKey(vault));
  }

  /// Serialise a packet to flat bytes.
  Uint8List packetSerialise(Packet pkt) {
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_packetSerialise(cpkt));
    } finally {
      _freePacketNative(cpkt);
    }
  }

  /// Deserialise flat bytes to a packet.
  Packet packetDeserialise(Uint8List data) {
    final pd = _toNative(data);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _packetDeserialise(pd, data.length, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pd != nullptr) calloc.free(pd);
      calloc.free(errPtr);
    }
  }

  /// Free a vault handle.
  void vaultFree(Pointer<Void> vault) => _vaultFree(vault);

  // ── Keyring (envelope / key-slots) ────────────────────────────────────────

  /// New keyring with a fresh random master key.
  Pointer<Void> keyringCreate() =>
      _lib.lookupFunction<Pointer<Void> Function(), Pointer<Void> Function()>(
          'cryptolib_keyring_create')();

  /// Wrap the master key under a >=32-byte hardware factor key.
  bool keyringAddDeviceSlot(Pointer<Void> kr, Uint8List factor) {
    final p = malloc<Uint8>(factor.length);
    p.asTypedList(factor.length).setAll(0, factor);
    try {
      return _lib.lookupFunction<Int32 Function(Pointer<Void>, Pointer<Uint8>, Size),
              int Function(Pointer<Void>, Pointer<Uint8>, int)>(
          'cryptolib_keyring_add_device_slot')(kr, p, factor.length) == 1;
    } finally {
      malloc.free(p);
    }
  }

  /// Wrap the master key under an Argon2id passphrase. kdf: 0=interactive, 1=sensitive.
  bool keyringAddPassphraseSlot(Pointer<Void> kr, String passphrase, int kdf) {
    final cpw = passphrase.toNativeUtf8();
    try {
      return _lib.lookupFunction<Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32),
              int Function(Pointer<Void>, Pointer<Utf8>, int)>(
          'cryptolib_keyring_add_passphrase_slot')(kr, cpw, kdf) == 1;
    } finally {
      malloc.free(cpw);
    }
  }

  /// Number of slots.
  int keyringSlotCount(Pointer<Void> kr) =>
      _lib.lookupFunction<Size Function(Pointer<Void>), int Function(Pointer<Void>)>(
          'cryptolib_keyring_slot_count')(kr);

  /// Remove (revoke) the slot at [index]. Returns true on success, false if the
  /// index is out of range.
  bool keyringRemoveSlot(Pointer<Void> kr, int index) =>
      _lib.lookupFunction<Int32 Function(Pointer<Void>, Size),
              int Function(Pointer<Void>, int)>(
          'cryptolib_keyring_remove_slot')(kr, index) == 1;

  /// Serialise the envelope blob (no plaintext key).
  Uint8List keyringSerialise(Pointer<Void> kr) => _checkBufResult(
      _lib.lookupFunction<CryptoBufferResult Function(Pointer<Void>),
              CryptoBufferResult Function(Pointer<Void>)>(
          'cryptolib_keyring_serialise')(kr));

  /// Parse an envelope blob into a (locked) keyring handle (nullptr on error).
  Pointer<Void> keyringDeserialise(Uint8List blob) {
    final p = malloc<Uint8>(blob.length);
    p.asTypedList(blob.length).setAll(0, blob);
    final errPtr = malloc<Pointer<Utf8>>()..value = nullptr;
    try {
      return _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_keyring_deserialise')(p, blob.length, errPtr);
    } finally {
      malloc.free(p);
      malloc.free(errPtr);
    }
  }

  /// Recover the master key with a device factor key.
  Uint8List keyringUnlockWithDevice(Pointer<Void> kr, Uint8List factor) {
    final p = malloc<Uint8>(factor.length);
    p.asTypedList(factor.length).setAll(0, factor);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>(
          'cryptolib_keyring_unlock_with_device')(kr, p, factor.length));
    } finally {
      malloc.free(p);
    }
  }

  /// Recover the master key with a passphrase.
  Uint8List keyringUnlockWithPassphrase(Pointer<Void> kr, String passphrase) {
    final cpw = passphrase.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Utf8>)>(
          'cryptolib_keyring_unlock_with_passphrase')(kr, cpw));
    } finally {
      malloc.free(cpw);
    }
  }

  /// Free a keyring handle.
  void keyringFree(Pointer<Void> kr) =>
      _lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
          'cryptolib_keyring_free')(kr);

  // ── Post-Quantum (ML-KEM / ML-DSA / SLH-DSA) ──────────────────────────────

  KeyPairResult mlKemKeygen(int level) => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(Int32), CryptoKeyPair Function(int)>(
          'cryptolib_ml_kem_keygen')(level));

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) mlKemEncapsulate(Uint8List publicKey, int level) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib.lookupFunction<
          CryptoKemEncapsResult Function(Pointer<Uint8>, Size, Int32, Pointer<Pointer<Utf8>>),
          CryptoKemEncapsResult Function(Pointer<Uint8>, int, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_ml_kem_encapsulate')(pp, publicKey.length, level, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      return _drainKemEncaps(r);
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  Uint8List mlKemDecapsulate(Uint8List ciphertext, Uint8List secretKey, int level) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_ml_kem_decapsulate')(cp, ciphertext.length, sp, secretKey.length, level));
    } finally { if (cp != nullptr) calloc.free(cp); if (sp != nullptr) calloc.free(sp); }
  }

  // ── Hybrid KEM (X25519 + ML-KEM-768) ──────────────────────────────────────

  KeyPairResult hybridKemKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_hybrid_kem_keygen')());

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) hybridKemEncapsulate(Uint8List publicKey) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib.lookupFunction<
          CryptoKemEncapsResult Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          CryptoKemEncapsResult Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_hybrid_kem_encapsulate')(pp, publicKey.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      return _drainKemEncaps(r);
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  Uint8List hybridKemDecapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hybrid_kem_decapsulate')(cp, ciphertext.length, sp, secretKey.length));
    } finally { if (cp != nullptr) calloc.free(cp); if (sp != nullptr) calloc.free(sp); }
  }

  // ── Hybrid signature (Ed25519 + ML-DSA-65) ────────────────────────────────
  // Both classical and post-quantum signatures must verify. Keys and the
  // signature are concatenated: ed25519_part || ml_dsa_part.

  KeyPairResult hybridSigKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_hybrid_sig_keygen')());

  Uint8List hybridSigSign(Uint8List msg, Uint8List secretKey) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hybrid_sig_sign')(mp, msg.length, sp, secretKey.length));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool hybridSigVerify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hybrid_sig_verify')(
              mp, msg.length, sgp, sig.length, pp, publicKey.length) == 1;
    } finally {
      if (mp != nullptr) calloc.free(mp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }

  KeyPairResult mlDsaKeygen(int level) => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(Int32), CryptoKeyPair Function(int)>(
          'cryptolib_ml_dsa_keygen')(level));

  Uint8List mlDsaSign(Uint8List msg, Uint8List secretKey, int level) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_ml_dsa_sign')(mp, msg.length, sp, secretKey.length, level));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool mlDsaVerify(Uint8List msg, Uint8List sig, Uint8List publicKey, int level) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_ml_dsa_verify')(mp, msg.length, sgp, sig.length, pp, publicKey.length, level) == 1;
    } finally { if (mp != nullptr) calloc.free(mp); if (sgp != nullptr) calloc.free(sgp); if (pp != nullptr) calloc.free(pp); }
  }

  KeyPairResult slhDsaKeygen(int level, int hash) => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(Int32, Int32), CryptoKeyPair Function(int, int)>(
          'cryptolib_slh_dsa_keygen')(level, hash));

  Uint8List slhDsaSign(Uint8List msg, Uint8List secretKey, int level, int hash) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int, int)>(
          'cryptolib_slh_dsa_sign')(mp, msg.length, sp, secretKey.length, level, hash));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool slhDsaVerify(Uint8List msg, Uint8List sig, Uint8List publicKey, int level, int hash) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Int32, Int32),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int, int)>(
          'cryptolib_slh_dsa_verify')(mp, msg.length, sgp, sig.length, pp, publicKey.length, level, hash) == 1;
    } finally { if (mp != nullptr) calloc.free(mp); if (sgp != nullptr) calloc.free(sgp); if (pp != nullptr) calloc.free(pp); }
  }

  // ── BLS12-381 ─────────────────────────────────────────────────────────────

  KeyPairResult blsKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_bls_keygen')());

  /// Deterministic BLS keygen from input key material. [ikm] must be >= 32
  /// bytes (per IRTF draft-irtf-cfrg-bls-signature KeyGen). Same IKM → same key.
  KeyPairResult blsKeygenFromIkm(Uint8List ikm) {
    if (ikm.length < 32) {
      throw ArgumentError('BLS keygen IKM must be >= 32 bytes, got ${ikm.length}');
    }
    final ip = _toNative(ikm);
    try {
      return _extractKeyPair(_lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int)>(
          'cryptolib_bls_keygen_from_ikm')(ip, ikm.length));
    } finally { if (ip != nullptr) calloc.free(ip); }
  }

  Uint8List blsSign(Uint8List msg, Uint8List secretKey) {
    final mp = _toNative(msg), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_bls_sign')(mp, msg.length, sp, secretKey.length));
    } finally { if (mp != nullptr) calloc.free(mp); if (sp != nullptr) calloc.free(sp); }
  }

  bool blsVerify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final mp = _toNative(msg), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_bls_verify')(mp, msg.length, sgp, sig.length, pp, publicKey.length) == 1;
    } finally { if (mp != nullptr) calloc.free(mp); if (sgp != nullptr) calloc.free(sgp); if (pp != nullptr) calloc.free(pp); }
  }

  /// Aggregate N BLS signatures (each a 96-byte compressed G2 point) into a
  /// single 96-byte signature. Throws if [sigs] is empty.
  Uint8List blsAggregate(List<Uint8List> sigs) {
    if (sigs.isEmpty) {
      throw ArgumentError('blsAggregate requires at least one signature');
    }
    final (ptrs, lens) = _toNativeList(sigs);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, Size),
          CryptoBufferResult Function(Pointer<Pointer<Uint8>>, Pointer<Size>, int)>(
          'cryptolib_bls_aggregate')(ptrs, lens, sigs.length));
    } finally {
      _freeNativeList(ptrs, lens, sigs.length);
    }
  }

  /// Verify an aggregate signature over N (message, public key) pairs in a
  /// single operation. [messages] and [publicKeys] must be the same length and
  /// positionally correspond. Returns true iff every signature is valid.
  bool blsAggregateVerify(
      List<Uint8List> messages, List<Uint8List> publicKeys, Uint8List aggSig) {
    if (messages.length != publicKeys.length) {
      throw ArgumentError(
          'blsAggregateVerify: messages (${messages.length}) and publicKeys '
          '(${publicKeys.length}) must have equal length');
    }
    if (messages.isEmpty) {
      throw ArgumentError('blsAggregateVerify requires at least one pair');
    }
    final count = messages.length;
    final (mPtrs, mLens) = _toNativeList(messages);
    final (pPtrs, pLens) = _toNativeList(publicKeys);
    final ap = _toNative(aggSig);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Pointer<Uint8>>, Pointer<Size>,
              Pointer<Pointer<Uint8>>, Pointer<Size>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Pointer<Uint8>>, Pointer<Size>,
              Pointer<Pointer<Uint8>>, Pointer<Size>, int, Pointer<Uint8>, int)>(
          'cryptolib_bls_aggregate_verify')(
              mPtrs, mLens, pPtrs, pLens, count, ap, aggSig.length) == 1;
    } finally {
      _freeNativeList(mPtrs, mLens, count);
      _freeNativeList(pPtrs, pLens, count);
      if (ap != nullptr) calloc.free(ap);
    }
  }

  // ── EVM / Bitcoin interop (Keccak-256, RIPEMD-160, secp256k1 ECDSA) ────────

  /// Keccak-256 (ORIGINAL padding, Ethereum). 32-byte digest. NOT SHA3-256.
  /// Used for tx hashing, contract-address derivation, ABI selectors, EIP-55.
  Uint8List keccak256(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>(
          'cryptolib_keccak256')(pm, msg.length));
    } finally { if (pm != nullptr) calloc.free(pm); }
  }

  /// RIPEMD-160. 20-byte digest. Bitcoin HASH160(x) = ripemd160(sha256(x)).
  Uint8List ripemd160(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>(
          'cryptolib_ripemd160')(pm, msg.length));
    } finally { if (pm != nullptr) calloc.free(pm); }
  }

  /// secp256k1 keypair: secretKey(32) + publicKey(65 uncompressed, 0x04‖X‖Y).
  KeyPairResult secp256k1Keygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_secp256k1_keygen')());

  /// Derive the public key from a 32-byte secret key.
  /// [compressed] true → 33 bytes (0x02/0x03‖X), false → 65 bytes (0x04‖X‖Y).
  Uint8List secp256k1Pubkey(Uint8List secretKey, {bool compressed = false}) {
    final sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, int)>(
          'cryptolib_secp256k1_pubkey')(sp, secretKey.length, compressed ? 1 : 0));
    } finally { if (sp != nullptr) calloc.free(sp); }
  }

  /// Sign a 32-byte [digest] (RFC6979 deterministic, low-S). Returns 65 bytes:
  /// r(32)‖s(32)‖recovery_id(1). The caller hashes first (Ethereum:
  /// keccak256(rlp(tx)); Bitcoin: sha256(sha256(preimage))).
  Uint8List secp256k1Sign(Uint8List digest, Uint8List secretKey) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 sign: digest must be 32 bytes, got ${digest.length}');
    }
    final dp = _toNative(digest), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>, int)>(
          'cryptolib_secp256k1_sign')(dp, sp, secretKey.length));
    } finally { if (dp != nullptr) calloc.free(dp); if (sp != nullptr) calloc.free(sp); }
  }

  /// Verify a 64-byte [sig] (r‖s) over a 32-byte [digest]. [publicKey] is 33 or
  /// 65 bytes. Low-S enforced (EIP-2 / BIP-62). Returns true if valid.
  bool secp256k1Verify(Uint8List digest, Uint8List sig, Uint8List publicKey) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 verify: digest must be 32 bytes');
    }
    final dp = _toNative(digest), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_secp256k1_verify')(dp, sgp, sig.length, pp, publicKey.length) == 1;
    } finally {
      if (dp != nullptr) calloc.free(dp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }

  /// Recover the 65-byte uncompressed public key from a 32-byte [digest] and a
  /// 65-byte recoverable [sig65] (r‖s‖recovery_id). Ethereum's ecrecover.
  Uint8List secp256k1Recover(Uint8List digest, Uint8List sig65) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 recover: digest must be 32 bytes');
    }
    if (sig65.length != 65) {
      throw ArgumentError('secp256k1 recover: signature must be 65 bytes (r‖s‖recid)');
    }
    final dp = _toNative(digest), sp = _toNative(sig65);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>),
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>)>(
          'cryptolib_secp256k1_recover')(dp, sp));
    } finally { if (dp != nullptr) calloc.free(dp); if (sp != nullptr) calloc.free(sp); }
  }

  // ── Asymmetric Vault ──────────────────────────────────────────────────────

  /// Generate a full asymmetric key bundle (X25519 + Ed25519).
  AsymBundleResult asymBundleGenerate() => _extractBundle(_asymBundleGenerate());

  /// Asymmetric vault seal: sender encrypts for recipient with signature.
  Packet asymVaultSeal(AsymBundleResult sender, Uint8List recipientBoxPub, Uint8List plaintext, String aad) {
    final csender = calloc<CryptoAsymBundle>();
    final sbp = _toNative(sender.boxPublic);
    final sbs = _toNative(sender.boxSecret);
    final ssp = _toNative(sender.signPublic);
    final sss = _toNative(sender.signSecret);
    csender.ref.boxPublic.data = sbp;
    csender.ref.boxPublic.len = sender.boxPublic.length;
    csender.ref.boxSecret.data = sbs;
    csender.ref.boxSecret.len = sender.boxSecret.length;
    csender.ref.signPublic.data = ssp;
    csender.ref.signPublic.len = sender.signPublic.length;
    csender.ref.signSecret.data = sss;
    csender.ref.signSecret.len = sender.signSecret.length;

    final prpub = _toNative(recipientBoxPub);
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();

    try {
      final cp = _asymVaultSeal(csender, prpub, recipientBoxPub.length, pp, plaintext.length, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      calloc.free(sbp);
      calloc.free(sbs);
      calloc.free(ssp);
      calloc.free(sss);
      calloc.free(csender);
      if (prpub != nullptr) calloc.free(prpub);
      if (pp != nullptr) calloc.free(pp);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Asymmetric vault open: recipient decrypts and verifies.
  Uint8List asymVaultOpen(Packet pkt, AsymBundleResult recipient, Uint8List senderSignPub, String aad) {
    final cpkt = _packetToNative(pkt);

    final crecip = calloc<CryptoAsymBundle>();
    final rbp = _toNative(recipient.boxPublic);
    final rbs = _toNative(recipient.boxSecret);
    final rsp = _toNative(recipient.signPublic);
    final rss = _toNative(recipient.signSecret);
    crecip.ref.boxPublic.data = rbp;
    crecip.ref.boxPublic.len = recipient.boxPublic.length;
    crecip.ref.boxSecret.data = rbs;
    crecip.ref.boxSecret.len = recipient.boxSecret.length;
    crecip.ref.signPublic.data = rsp;
    crecip.ref.signPublic.len = recipient.signPublic.length;
    crecip.ref.signSecret.data = rss;
    crecip.ref.signSecret.len = recipient.signSecret.length;

    final psspub = _toNative(senderSignPub);
    final caad = aad.toNativeUtf8();

    try {
      return _checkBufResult(_asymVaultOpen(cpkt, crecip, psspub, senderSignPub.length, caad));
    } finally {
      _freePacketNative(cpkt);
      calloc.free(rbp);
      calloc.free(rbs);
      calloc.free(rsp);
      calloc.free(rss);
      calloc.free(crecip);
      if (psspub != nullptr) calloc.free(psspub);
      calloc.free(caad);
    }
  }

  // ── Media Entropy ─────────────────────────────────────────────────────────

  /// Harvest entropy from a file (LavaRand mode).
  Pointer<Void> entropyFromFile(String path) {
    final cp = path.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFile(cp, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      calloc.free(cp);
      calloc.free(errPtr);
    }
  }

  /// Harvest entropy from a file (deterministic mode).
  Pointer<Void> entropyFromFileDeterministic(String path) {
    final cp = path.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFileDet(cp, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      calloc.free(cp);
      calloc.free(errPtr);
    }
  }

  /// Harvest entropy from multiple files (LavaRand mode).
  Pointer<Void> entropyFromFiles(List<String> paths) {
    final pathPtrs = calloc<Pointer<Utf8>>(paths.length);
    for (int i = 0; i < paths.length; i++) {
      pathPtrs[i] = paths[i].toNativeUtf8();
    }
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFiles(pathPtrs, paths.length, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      for (int i = 0; i < paths.length; i++) {
        calloc.free(pathPtrs[i]);
      }
      calloc.free(pathPtrs);
      calloc.free(errPtr);
    }
  }

  /// Harvest entropy from multiple files (deterministic mode).
  Pointer<Void> entropyFromFilesDeterministic(List<String> paths) {
    final pathPtrs = calloc<Pointer<Utf8>>(paths.length);
    for (int i = 0; i < paths.length; i++) {
      pathPtrs[i] = paths[i].toNativeUtf8();
    }
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFilesDet(pathPtrs, paths.length, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      for (int i = 0; i < paths.length; i++) {
        calloc.free(pathPtrs[i]);
      }
      calloc.free(pathPtrs);
      calloc.free(errPtr);
    }
  }

  /// Derive all 6 domain-separated keys at once.
  DerivedKeysResult entropyDeriveAll(Pointer<Void> handle) {
    final dk = _entropyDeriveAll(handle);
    return DerivedKeysResult(
      symmetricKey: _copyBuf(dk.symmetricKey),
      vaultMasterKey: _copyBuf(dk.vaultMasterKey),
      signingSeed: _copyBuf(dk.signingSeed),
      boxSeed: _copyBuf(dk.boxSeed),
      streamKey: _copyBuf(dk.streamKey),
      rawEntropy: _copyBuf(dk.rawEntropy),
    );
  }

  /// Derive a 32-byte symmetric key from an entropy handle.
  Uint8List entropySymmetricKey(Pointer<Void> handle) {
    return _checkBufResult(_entropySymKey(handle));
  }

  /// Get the 64-byte raw mixed entropy.
  Uint8List entropyRaw(Pointer<Void> handle) {
    return _checkBufResult(_entropyRaw(handle));
  }

  /// Get the 32-byte entropy boost key.
  Uint8List entropyBoost(Pointer<Void> handle) {
    return _checkBufResult(_entropyBoost(handle));
  }

  /// Get entropy info.
  EntropyInfoResult entropyInfo(Pointer<Void> handle) {
    final info = _entropyInfo(handle);
    final result = EntropyInfoResult(
      path: info.path.toDartString(),
      fileSize: info.fileSize,
      chunksRead: info.chunksRead,
      entropyBits: info.entropyBits,
    );
    _strFree(info.path);
    return result;
  }

  /// Get a full asymmetric bundle from entropy.
  AsymBundleResult entropyAsymBundle(Pointer<Void> handle) {
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final ab = _entropyAsymBundle(handle, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return _extractBundle(ab);
    } finally {
      calloc.free(errPtr);
    }
  }

  /// Refresh system entropy in-place.
  void entropyRefresh(Pointer<Void> handle) => _entropyRefresh(handle);

  /// Free an entropy handle.
  void entropyFree(Pointer<Void> handle) => _entropyFree(handle);

  // ── Entropy convenience ───────────────────────────────────────────────────

  /// One-liner: get a 32-byte key from any file.
  Uint8List keyFromFile(String path) {
    final cp = path.toNativeUtf8();
    try {
      return _checkBufResult(_keyFromFile(cp));
    } finally {
      calloc.free(cp);
    }
  }

  /// One-liner: encrypt plaintext using a file as the key.
  Packet sealFromFile(String path, String plaintext, String aad) {
    final cpath = path.toNativeUtf8();
    final cpt = plaintext.toNativeUtf8();
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _sealFromFile(cpath, cpt, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      calloc.free(cpath);
      calloc.free(cpt);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// One-liner: decrypt a packet using a file as the key.
  Uint8List openFromFile(String path, Packet pkt, String aad) {
    final cpath = path.toNativeUtf8();
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_openFromFile(cpath, cpkt, caad));
    } finally {
      calloc.free(cpath);
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

  // ── Steganography ─────────────────────────────────────────────────────────

  /// Embed raw bytes into a media file.
  void stegoEmbed(String coverPath, Uint8List payload, String outputPath) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(payload);
    final co = outputPath.toNativeUtf8();
    try {
      final r = _stegoEmbed(cc, pp, payload.length, co);
      _checkResult(r);
    } finally {
      calloc.free(cc);
      if (pp != nullptr) calloc.free(pp);
      calloc.free(co);
    }
  }

  /// Extract raw bytes from a stego media file.
  Uint8List stegoExtract(String stegoPath) {
    final cp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(_stegoExtract(cp));
    } finally {
      calloc.free(cp);
    }
  }

  /// Get the steganographic capacity of a cover file (in bytes).
  int stegoCapacity(String coverPath) {
    final cp = coverPath.toNativeUtf8();
    try {
      return _stegoCapacity(cp);
    } finally {
      calloc.free(cp);
    }
  }
}

/// Hex encoding helper.
String toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Hex decoding helper.
Uint8List fromHex(String hex) {
  final result = Uint8List(hex.length ~/ 2);
  for (int i = 0; i < result.length; i++) {
    result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}
