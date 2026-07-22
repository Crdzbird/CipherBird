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
import 'dart:io';
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

final class CryptoFrostKeyGen extends Struct {
  external CryptoBuffer groupPublicKey;
  external CryptoBuffer secretShares;
  external CryptoBuffer publicShares;

  @Size()
  external int count;
  external Pointer<Utf8> error;
}

final class CryptoFrostCommit extends Struct {
  external CryptoBuffer hidingNonce;
  external CryptoBuffer bindingNonce;
  external CryptoBuffer hidingCommit;
  external CryptoBuffer bindingCommit;
  external Pointer<Utf8> error;
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

/// Public metadata of a sealed (Flagship/Fortress) envelope. No secrets.
final class CryptoSealedInfo extends Struct {
  @Uint8()
  external int ok;
  @Uint8()
  external int version;
  @Uint8()
  external int suite;
  @Uint8()
  external int streaming;
  @Array(16)
  external Array<Uint8> fingerprint;
  @Size()
  external int kemCiphertextLen;
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

  /// Load the native library. Resolution order:
  ///   1. an explicit [path],
  ///   2. the CRYPTOLIB_DYLIB environment variable (dev override),
  ///   3. the library BUNDLED with this package under native/<os>-<arch>/
  ///      (so the package is self-contained — no build tree required),
  ///   4. the current process (symbols already loaded, e.g. a Flutter plugin).
  factory CryptoLib.load([String? path]) {
    path ??= Platform.environment['CRYPTOLIB_DYLIB'];
    path ??= _bundledLibPath();
    final lib = path != null ? DynamicLibrary.open(path) : DynamicLibrary.process();
    return CryptoLib._(lib);
  }

  /// Locate the native library bundled inside this package for the host
  /// platform. Returns null if not found (caller falls back to process()).
  static String? _bundledLibPath() {
    final os = Platform.isMacOS
        ? 'darwin'
        : Platform.isLinux
            ? 'linux'
            : Platform.isWindows
                ? 'windows'
                : null;
    if (os == null) return null;
    final ext = Platform.isMacOS ? 'dylib' : (Platform.isWindows ? 'dll' : 'so');
    final abi = Abi.current();
    final arch = (abi == Abi.macosArm64 || abi == Abi.linuxArm64 || abi == Abi.windowsArm64)
        ? 'arm64'
        : (abi == Abi.macosX64 || abi == Abi.linuxX64 || abi == Abi.windowsX64)
            ? 'x64'
            : null;
    if (arch == null) return null;
    final rel = 'native/$os-$arch/libcryptolib_c.$ext';
    final roots = <String>[
      '', // relative to cwd
      '${Directory.current.path}/',
      if (Platform.script.scheme == 'file')
        '${File.fromUri(Platform.script).parent.parent.path}/', // package root from bin/
    ];
    for (final root in roots) {
      final candidate = '$root$rel';
      if (File(candidate).existsSync()) return candidate;
    }
    return null;
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

  // ── Hybrid KEM (X25519 + sntrup761) ───────────────────────────────────────
  // Second hybrid using NTRU Prime — a different lattice family for diversity.

  KeyPairResult sntrupX25519Keygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_sntrup_x25519_keygen')());

  /// Returns (ciphertext, sharedSecret).
  (Uint8List, Uint8List) sntrupX25519Encapsulate(Uint8List publicKey) {
    final pp = _toNative(publicKey);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final r = _lib.lookupFunction<
          CryptoKemEncapsResult Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          CryptoKemEncapsResult Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_sntrup_x25519_encapsulate')(pp, publicKey.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      return _drainKemEncaps(r);
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  Uint8List sntrupX25519Decapsulate(Uint8List ciphertext, Uint8List secretKey) {
    final cp = _toNative(ciphertext), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_sntrup_x25519_decapsulate')(cp, ciphertext.length, sp, secretKey.length));
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

  // ── MolecularVault — maximum-assurance layered encryption ──────────────────
  // Cascade XChaCha20-Poly1305 ∘ AES-256-GCM-SIV under a key-committing outer
  // layer, keyed by Argon2id(passphrase) or a 32-byte full-entropy master.

  /// Seal [plaintext] under a [passphrase]. [ops]/[mem] are Argon2id work
  /// factors; pass 0 for either to use the library's SENSITIVE preset. Raise
  /// [mem] toward 1<<30 (1 GiB) to make password guessing far costlier.
  Uint8List molecularSeal(Uint8List plaintext, String passphrase,
      {Uint8List? aad, int ops = 0, int mem = 0}) {
    final pp = _toNative(plaintext);
    final cpw = passphrase.toNativeUtf8();
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Utf8>,
              Pointer<Uint8>, Size, Uint64, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>,
              Pointer<Uint8>, int, int, int)>('cryptolib_molecular_seal')(
          pp, plaintext.length, cpw, pa, aad?.length ?? 0, ops, mem));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(cpw);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Open a passphrase-sealed envelope. Wrong passphrase/AAD or tampering throws.
  Uint8List molecularOpen(Uint8List envelope, String passphrase, {Uint8List? aad}) {
    final pe = _toNative(envelope);
    final cpw = passphrase.toNativeUtf8();
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>,
              Pointer<Uint8>, int)>('cryptolib_molecular_open')(
          pe, envelope.length, cpw, pa, aad?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      calloc.free(cpw);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Seal under a 32-byte full-entropy master key (e.g. from the hybrid KEM).
  Uint8List molecularSealWithKey(Uint8List plaintext, Uint8List masterKey,
      {Uint8List? aad}) {
    final pp = _toNative(plaintext), pk = _toNative(masterKey);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('cryptolib_molecular_seal_with_key')(
          pp, plaintext.length, pk, masterKey.length, pa, aad?.length ?? 0));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Open a raw-key-sealed envelope.
  Uint8List molecularOpenWithKey(Uint8List envelope, Uint8List masterKey,
      {Uint8List? aad}) {
    final pe = _toNative(envelope), pk = _toNative(masterKey);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('cryptolib_molecular_open_with_key')(
          pe, envelope.length, pk, masterKey.length, pa, aad?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  // ── Suite — one-call advanced combinations (needs OpenSSL + PQ) ──
  /// Post-quantum message: encapsulate to [recipientKemPublic] and seal under
  /// the shared secret. Secure while EITHER X25519 or ML-KEM-768 holds.
  Uint8List suiteSealPq(Uint8List plaintext, Uint8List recipientKemPublic,
          {Uint8List? aad}) =>
      _suiteBuf('cryptolib_suite_seal_pq', plaintext, recipientKemPublic, aad);

  /// Like [suiteSealPq] but with the X25519+sntrup761 hybrid KEM (a different
  /// lattice family). [suiteOpenPq] auto-detects the KEM from the envelope.
  Uint8List suiteSealPqSntrup(Uint8List plaintext, Uint8List recipientKemPublic,
          {Uint8List? aad}) =>
      _suiteBuf('cryptolib_suite_seal_pq_sntrup', plaintext, recipientKemPublic, aad);

  /// Open a [suiteSealPq]/[suiteSealPqSntrup] envelope with the recipient's
  /// hybrid-KEM secret key (KEM chosen from the envelope's suite id).
  Uint8List suiteOpenPq(Uint8List envelope, Uint8List recipientKemSecret,
          {Uint8List? aad}) =>
      _suiteBuf('cryptolib_suite_open_pq', envelope, recipientKemSecret, aad);

  /// Flagship: post-quantum confidentiality (hybrid KEM) + post-quantum
  /// authenticity (Ed25519+ML-DSA-65). [suiteOpenSignedPq] returns plaintext
  /// only if the signature verifies.
  Uint8List suiteSealSignedPq(Uint8List plaintext, Uint8List recipientKemPublic,
          Uint8List signerSigSecret, {Uint8List? aad}) =>
      _suiteBuf3('cryptolib_suite_seal_signed_pq', plaintext, recipientKemPublic,
          signerSigSecret, aad);

  /// Flagship with the X25519+sntrup761 hybrid KEM.
  Uint8List suiteSealSignedPqSntrup(Uint8List plaintext, Uint8List recipientKemPublic,
          Uint8List signerSigSecret, {Uint8List? aad}) =>
      _suiteBuf3('cryptolib_suite_seal_signed_pq_sntrup', plaintext, recipientKemPublic,
          signerSigSecret, aad);

  /// Decrypt then verify; a signature mismatch throws and yields no plaintext.
  Uint8List suiteOpenSignedPq(Uint8List envelope, Uint8List recipientKemSecret,
          Uint8List signerSigPublic, {Uint8List? aad}) =>
      _suiteBuf3('cryptolib_suite_open_signed_pq', envelope, recipientKemSecret,
          signerSigPublic, aad);

  /// File-as-key: deterministic media entropy from [path] derives the master.
  Uint8List suiteSealWithFile(Uint8List plaintext, String path, {Uint8List? aad}) =>
      _suiteFile('cryptolib_suite_seal_with_file', plaintext, path, aad);

  /// Re-derive from the same file and open the envelope.
  Uint8List suiteOpenWithFile(Uint8List envelope, String path, {Uint8List? aad}) =>
      _suiteFile('cryptolib_suite_open_with_file', envelope, path, aad);

  /// Keyring-guarded: a device-factor unlock provides the MolecularVault master.
  Uint8List suiteSealWithKeyringDevice(Uint8List plaintext, Pointer<Void> keyring,
          Uint8List factorKey, {Uint8List? aad}) =>
      _suiteKeyringFactor('cryptolib_suite_seal_with_keyring_device', plaintext,
          keyring, factorKey, aad);

  Uint8List suiteOpenWithKeyringDevice(Uint8List envelope, Pointer<Void> keyring,
          Uint8List factorKey, {Uint8List? aad}) =>
      _suiteKeyringFactor('cryptolib_suite_open_with_keyring_device', envelope,
          keyring, factorKey, aad);

  /// Keyring-guarded via a passphrase slot.
  Uint8List suiteSealWithKeyringPassphrase(Uint8List plaintext,
          Pointer<Void> keyring, String passphrase, {Uint8List? aad}) =>
      _suiteKeyringPass('cryptolib_suite_seal_with_keyring_passphrase', plaintext,
          keyring, passphrase, aad);

  Uint8List suiteOpenWithKeyringPassphrase(Uint8List envelope,
          Pointer<Void> keyring, String passphrase, {Uint8List? aad}) =>
      _suiteKeyringPass('cryptolib_suite_open_with_keyring_passphrase', envelope,
          keyring, passphrase, aad);

  /// EVM address (20 bytes) from a 65-byte uncompressed secp256k1 public key.
  Uint8List suiteEvmAddress(Uint8List secp256k1PublicKey) {
    final pk = _toNative(secp256k1PublicKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>(
          'cryptolib_suite_evm_address')(pk, secp256k1PublicKey.length));
    } finally {
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Threshold (k-of-n): seal under a fresh master, split it into [n] Shamir
  /// shares of which any [k] reconstruct it. Returns the envelope and the [n]
  /// individual share records; distribute the shares, keep the envelope
  /// anywhere. Open with [suiteOpenThreshold] using any `k` of the shares.
  (Uint8List envelope, List<Uint8List> shares) suiteSealThreshold(
      Uint8List plaintext, int n, int k, {Uint8List? aad}) {
    final pp = _toNative(plaintext);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final outShares = calloc<CryptoBuffer>();
    try {
      final r = _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Uint8, Uint8,
              Pointer<Uint8>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Uint8>, int, int, int,
              Pointer<Uint8>, int, Pointer<CryptoBuffer>)>(
          'cryptolib_suite_seal_threshold')(
          pp, plaintext.length, n, k, pa, aad?.length ?? 0, outShares);
      final env = _checkBufResult(r); // throws on error (outShares stays empty)
      final blob = _copyBuf(outShares.ref);
      return (env, _splitShareRecords(blob));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pa != nullptr) calloc.free(pa);
      calloc.free(outShares);
    }
  }

  /// Reconstruct the master from any k of the shares and open the envelope.
  Uint8List suiteOpenThreshold(Uint8List envelope, List<Uint8List> shares,
      {Uint8List? aad}) {
    final blob = BytesBuilder();
    for (final s in shares) {
      blob.add(s);
    }
    final joined = blob.toBytes();
    final pe = _toNative(envelope);
    final ps = _toNative(joined);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('cryptolib_suite_open_threshold')(
          pe, envelope.length, ps, joined.length, pa, aad?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (ps != nullptr) calloc.free(ps);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  // ── shared plumbing ───────────────────────────────────────────────────────

  Uint8List _suiteBuf(String symbol, Uint8List a, Uint8List b, Uint8List? aad) {
    final pa = _toNative(a), pb = _toNative(b);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>(symbol)(
          pa, a.length, pb, b.length, pad, aad?.length ?? 0));
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteBuf3(String symbol, Uint8List a, Uint8List b, Uint8List c,
      Uint8List? aad) {
    final pa = _toNative(a), pb = _toNative(b), pc = _toNative(c);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          pa, a.length, pb, b.length, pc, c.length, pad, aad?.length ?? 0));
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
      if (pc != nullptr) calloc.free(pc);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteFile(String symbol, Uint8List data, String path, Uint8List? aad) {
    final pd = _toNative(data);
    final cp = path.toNativeUtf8();
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>,
              Pointer<Uint8>, int)>(symbol)(
          pd, data.length, cp, pad, aad?.length ?? 0));
    } finally {
      if (pd != nullptr) calloc.free(pd);
      calloc.free(cp);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteKeyringFactor(String symbol, Uint8List data,
      Pointer<Void> keyring, Uint8List factor, Uint8List? aad) {
    final pd = _toNative(data), pf = _toNative(factor);
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Void>,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Void>,
              Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          pd, data.length, keyring, pf, factor.length, pad, aad?.length ?? 0));
    } finally {
      if (pd != nullptr) calloc.free(pd);
      if (pf != nullptr) calloc.free(pf);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  Uint8List _suiteKeyringPass(String symbol, Uint8List data,
      Pointer<Void> keyring, String passphrase, Uint8List? aad) {
    final pd = _toNative(data);
    final cpw = passphrase.toNativeUtf8();
    final pad = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Void>,
              Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Void>,
              Pointer<Utf8>, Pointer<Uint8>, int)>(symbol)(
          pd, data.length, keyring, cpw, pad, aad?.length ?? 0));
    } finally {
      if (pd != nullptr) calloc.free(pd);
      calloc.free(cpw);
      if (pad != nullptr) calloc.free(pad);
    }
  }

  // Parse [index(1)|ylen(4 LE)|y] records into individual share byte-slices.
  List<Uint8List> _splitShareRecords(Uint8List blob) {
    final out = <Uint8List>[];
    var off = 0;
    while (off + 5 <= blob.length) {
      final yl = blob[off + 1] | (blob[off + 2] << 8) | (blob[off + 3] << 16) | (blob[off + 4] << 24);
      final end = off + 5 + yl;
      if (end > blob.length) break;
      out.add(Uint8List.sublistView(blob, off, end));
      off = end;
    }
    return out;
  }

  // ── Flagship / Fortress sealed messaging (tier 0=Flagship, 1=Fortress) ─────
  /// Generate a party's recipient (KEM) + sender (signature) keypairs.
  Identity newIdentity(SealedTier tier) {
    final r = _extractKeyPair(_lib.lookupFunction<CryptoKeyPair Function(Int32),
        CryptoKeyPair Function(int)>('cryptolib_sealed_generate_recipient')(tier.index));
    final s = _extractKeyPair(_lib.lookupFunction<CryptoKeyPair Function(Int32),
        CryptoKeyPair Function(int)>('cryptolib_sealed_generate_sender')(tier.index));
    return Identity(this, tier, r.publicKey, r.secretKey, s.publicKey, s.secretKey);
  }

  /// Read an envelope's public header without any key. Null if unrecognizable.
  SealedInfo? sealedInspect(Uint8List envelope) {
    final pe = _toNative(envelope);
    try {
      final info = _lib.lookupFunction<CryptoSealedInfo Function(Pointer<Uint8>, Size),
          CryptoSealedInfo Function(Pointer<Uint8>, int)>('cryptolib_sealed_inspect')(pe, envelope.length);
      if (info.ok == 0) return null;
      final fp = Uint8List(16);
      for (var i = 0; i < 16; i++) { fp[i] = info.fingerprint[i]; }
      return SealedInfo(
          version: info.version, suite: info.suite, streaming: info.streaming == 1,
          fingerprint: fp, kemCiphertextLen: info.kemCiphertextLen);
    } finally {
      if (pe != nullptr) calloc.free(pe);
    }
  }

  /// Whether the envelope is addressed to recipientPublic (fingerprint match).
  bool sealedAddressedTo(Uint8List envelope, Uint8List recipientPublic) {
    final pe = _toNative(envelope), pr = _toNative(recipientPublic);
    try {
      return _lib.lookupFunction<Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
              int Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_sealed_addressed_to')(
          pe, envelope.length, pr, recipientPublic.length) == 1;
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (pr != nullptr) calloc.free(pr);
    }
  }

  Uint8List sealedSeal(SealedTier tier, Uint8List pt, Uint8List recipientPublic,
      Uint8List senderSecret, {Uint8List? aad, Uint8List? purpose}) {
    final pp = _toNative(pt), pr = _toNative(recipientPublic), ps = _toNative(senderSecret);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_sealed_seal')(
          tier.index, pp, pt.length, pr, recipientPublic.length, ps, senderSecret.length,
          pa, aad?.length ?? 0, pu, purpose?.length ?? 0));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pr != nullptr) calloc.free(pr);
      if (ps != nullptr) calloc.free(ps);
      if (pa != nullptr) calloc.free(pa);
      if (pu != nullptr) calloc.free(pu);
    }
  }

  Uint8List sealedOpen(SealedTier tier, Uint8List envelope, Uint8List recipientSecret,
      Uint8List recipientPublic, Uint8List senderPublic, {Uint8List? aad, Uint8List? purpose}) {
    final pe = _toNative(envelope), prs = _toNative(recipientSecret),
        prp = _toNative(recipientPublic), psp = _toNative(senderPublic);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_sealed_open')(
          tier.index, pe, envelope.length, prs, recipientSecret.length, prp, recipientPublic.length,
          psp, senderPublic.length, pa, aad?.length ?? 0, pu, purpose?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (prs != nullptr) calloc.free(prs);
      if (prp != nullptr) calloc.free(prp);
      if (psp != nullptr) calloc.free(psp);
      if (pa != nullptr) calloc.free(pa);
      if (pu != nullptr) calloc.free(pu);
    }
  }

  SealedStreamSealer sealedSealerBegin(SealedTier tier, Uint8List recipientPublic,
      Uint8List senderSecret, {Uint8List? purpose}) {
    final pr = _toNative(recipientPublic), ps = _toNative(senderSecret);
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_sealed_sealer_begin')(
          tier.index, pr, recipientPublic.length, ps, senderSecret.length, pu, purpose?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: stream sealer begin failed');
      return SealedStreamSealer(this, h);
    } finally {
      if (pr != nullptr) calloc.free(pr);
      if (ps != nullptr) calloc.free(ps);
      if (pu != nullptr) calloc.free(pu);
      calloc.free(errPtr);
    }
  }

  Uint8List _sealedSealerPreamble(Pointer<Void> h) => _checkBufResult(_lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>), CryptoBufferResult Function(Pointer<Void>)>('cryptolib_sealed_sealer_preamble')(h));

  Uint8List _sealedSealerPush(Pointer<Void> h, Uint8List chunk) {
    final pc = _toNative(chunk);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>('cryptolib_sealed_sealer_push')(h, pc, chunk.length));
    } finally { if (pc != nullptr) calloc.free(pc); }
  }

  (Uint8List, Uint8List) _sealedSealerFinalize(Pointer<Void> h, Uint8List? last) {
    final pl = (last != null && last.isNotEmpty) ? _toNative(last) : nullptr;
    final outTrailer = calloc<CryptoBuffer>();
    try {
      final ct = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<CryptoBuffer>),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<CryptoBuffer>)>('cryptolib_sealed_sealer_finalize')(
          h, pl, last?.length ?? 0, outTrailer));
      return (ct, _copyBuf(outTrailer.ref));
    } finally { if (pl != nullptr) calloc.free(pl); calloc.free(outTrailer); }
  }

  void _sealedSealerFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_sealed_sealer_free')(h);

  SealedStreamOpener sealedOpenerBegin(SealedTier tier, Uint8List preamble,
      Uint8List recipientSecret, Uint8List recipientPublic, Uint8List senderPublic, {Uint8List? purpose}) {
    final pp = _toNative(preamble), prs = _toNative(recipientSecret),
        prp = _toNative(recipientPublic), psp = _toNative(senderPublic);
    final pu = (purpose != null && purpose.isNotEmpty) ? _toNative(purpose) : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_sealed_opener_begin')(
          tier.index, pp, preamble.length, prs, recipientSecret.length, prp, recipientPublic.length,
          psp, senderPublic.length, pu, purpose?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: stream opener begin failed');
      return SealedStreamOpener(this, h);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (prs != nullptr) calloc.free(prs);
      if (prp != nullptr) calloc.free(prp);
      if (psp != nullptr) calloc.free(psp);
      if (pu != nullptr) calloc.free(pu);
      calloc.free(errPtr);
    }
  }

  (Uint8List, bool) _sealedOpenerPull(Pointer<Void> h, Uint8List ct) {
    final pc = _toNative(ct);
    final outFinal = calloc<Int32>();
    try {
      final pt = _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Int32>),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Int32>)>('cryptolib_sealed_opener_pull')(h, pc, ct.length, outFinal));
      return (pt, outFinal.value == 1);
    } finally { if (pc != nullptr) calloc.free(pc); calloc.free(outFinal); }
  }

  void _sealedOpenerFinalize(Pointer<Void> h, Uint8List trailer) {
    final pt = _toNative(trailer);
    try {
      _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>('cryptolib_sealed_opener_finalize')(h, pt, trailer.length));
    } finally { if (pt != nullptr) calloc.free(pt); }
  }

  void _sealedOpenerFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_sealed_opener_free')(h);

  // ── Session — PQ forward-secret ratchet (hybrid KEM Double Ratchet) ────────
  /// Responder: generate a prekey (hybrid-KEM keypair). Publish publicKey.
  KeyPairResult generateSessionPrekey() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_session_generate_prekey')());

  /// Initiator: start a session to the responder's prekey public key.
  Session initiateSession(Uint8List responderPrekeyPublic) {
    final pp = _toNative(responderPrekeyPublic);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_session_initiate')(
          pp, responderPrekeyPublic.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: session initiate failed');
      return Session(this, h);
    } finally { if (pp != nullptr) calloc.free(pp); calloc.free(errPtr); }
  }

  /// Responder: accept a handshake with your prekey (public + secret).
  Session acceptSession(Uint8List handshake, Uint8List prekeyPublic, Uint8List prekeySecret) {
    final ph = _toNative(handshake), pub = _toNative(prekeyPublic), sec = _toNative(prekeySecret);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_session_accept')(
          ph, handshake.length, pub, prekeyPublic.length, sec, prekeySecret.length, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: session accept failed');
      return Session(this, h);
    } finally {
      if (ph != nullptr) calloc.free(ph);
      if (pub != nullptr) calloc.free(pub);
      if (sec != nullptr) calloc.free(sec);
      calloc.free(errPtr);
    }
  }

  Uint8List _sessionHandshake(Pointer<Void> h) => _checkBufResult(_lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>), CryptoBufferResult Function(Pointer<Void>)>('cryptolib_session_handshake')(h));

  Uint8List _sessionMsg(String symbol, Pointer<Void> h, Uint8List data, Uint8List? aad) {
    final pd = _toNative(data);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          h, pd, data.length, pa, aad?.length ?? 0));
    } finally { if (pd != nullptr) calloc.free(pd); if (pa != nullptr) calloc.free(pa); }
  }

  void _sessionFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_session_free')(h);

  // ── FROST(Ed25519, SHA-512) — t-of-n threshold signatures (RFC 9591) ───────
  /// Trusted-dealer split: any [t] of [n] shares can sign. Share i (0-based) has
  /// FROST identifier i+1. Output verifies with standard Ed25519 verification.
  FrostKeyGen frostKeygen(int n, int t) {
    final kg = _lib.lookupFunction<
        CryptoFrostKeyGen Function(Uint16, Uint16),
        CryptoFrostKeyGen Function(int, int)>('cryptolib_frost_keygen')(n, t);
    if (kg.error != nullptr) {
      final m = kg.error.toDartString();
      _frostKeygenFree(kg);
      throw Exception(m);
    }
    final count = kg.count;
    final gpk = _copyBufView(kg.groupPublicKey);
    final secs = _copyBufView(kg.secretShares);
    final pubs = _copyBufView(kg.publicShares);
    _frostKeygenFree(kg);
    final secretShares = <Uint8List>[];
    final publicShares = <Uint8List>[];
    for (var i = 0; i < count; i++) {
      secretShares.add(Uint8List.sublistView(secs, i * 32, i * 32 + 32));
      publicShares.add(Uint8List.sublistView(pubs, i * 32, i * 32 + 32));
    }
    return FrostKeyGen(gpk, secretShares, publicShares);
  }

  void _frostKeygenFree(CryptoFrostKeyGen kg) {
    final p = calloc<CryptoFrostKeyGen>();
    p.ref.groupPublicKey.data = kg.groupPublicKey.data;
    p.ref.groupPublicKey.len = kg.groupPublicKey.len;
    p.ref.secretShares.data = kg.secretShares.data;
    p.ref.secretShares.len = kg.secretShares.len;
    p.ref.publicShares.data = kg.publicShares.data;
    p.ref.publicShares.len = kg.publicShares.len;
    p.ref.count = kg.count;
    p.ref.error = kg.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoFrostKeyGen>),
        void Function(Pointer<CryptoFrostKeyGen>)>('cryptolib_frost_keygen_free')(p);
    calloc.free(p);
  }

  /// Round 1: fresh random nonce pair + public commitment for a share. Keep the
  /// returned nonces secret; publish the commitment.
  (FrostNonces, FrostCommitment) frostCommit(Uint8List shareSecret, int identifier) {
    final ps = _toNative(shareSecret);
    try {
      final c = _lib.lookupFunction<
          CryptoFrostCommit Function(Pointer<Uint8>, Size, Uint16),
          CryptoFrostCommit Function(Pointer<Uint8>, int, int)>('cryptolib_frost_commit')(
          ps, shareSecret.length, identifier);
      return _frostCommitOut(c, identifier);
    } finally { if (ps != nullptr) calloc.free(ps); }
  }

  /// Deterministic round-1 commit from caller-supplied nonces (test vectors).
  (FrostNonces, FrostCommitment) frostCommitWithNonces(int identifier, Uint8List hiding, Uint8List binding) {
    final ph = _toNative(hiding), pb = _toNative(binding);
    try {
      final c = _lib.lookupFunction<
          CryptoFrostCommit Function(Uint16, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoFrostCommit Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_frost_commit_with_nonces')(
          identifier, ph, hiding.length, pb, binding.length);
      return _frostCommitOut(c, identifier);
    } finally { if (ph != nullptr) calloc.free(ph); if (pb != nullptr) calloc.free(pb); }
  }

  (FrostNonces, FrostCommitment) _frostCommitOut(CryptoFrostCommit c, int identifier) {
    if (c.error != nullptr) {
      final m = c.error.toDartString();
      _frostCommitFree(c);
      throw Exception(m);
    }
    final nonces = FrostNonces(_copyBufView(c.hidingNonce), _copyBufView(c.bindingNonce));
    final commit = FrostCommitment(identifier, _copyBufView(c.hidingCommit), _copyBufView(c.bindingCommit));
    _frostCommitFree(c);
    return (nonces, commit);
  }

  void _frostCommitFree(CryptoFrostCommit c) {
    final p = calloc<CryptoFrostCommit>();
    p.ref.hidingNonce.data = c.hidingNonce.data;     p.ref.hidingNonce.len = c.hidingNonce.len;
    p.ref.bindingNonce.data = c.bindingNonce.data;   p.ref.bindingNonce.len = c.bindingNonce.len;
    p.ref.hidingCommit.data = c.hidingCommit.data;   p.ref.hidingCommit.len = c.hidingCommit.len;
    p.ref.bindingCommit.data = c.bindingCommit.data; p.ref.bindingCommit.len = c.bindingCommit.len;
    p.ref.error = c.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoFrostCommit>),
        void Function(Pointer<CryptoFrostCommit>)>('cryptolib_frost_commit_free')(p);
    calloc.free(p);
  }

  // Flatten commitments into the three parallel wire arrays (caller frees them).
  (Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>) _frostBufs(List<FrostCommitment> cs) {
    final n = cs.length;
    final ids = calloc<Uint16>(n == 0 ? 1 : n);
    final hid = calloc<Uint8>(n == 0 ? 1 : n * 32);
    final bnd = calloc<Uint8>(n == 0 ? 1 : n * 32);
    if (n > 0) {
      final hidList = hid.asTypedList(n * 32);
      final bndList = bnd.asTypedList(n * 32);
      for (var i = 0; i < n; i++) {
        ids[i] = cs[i].identifier;
        hidList.setAll(i * 32, cs[i].hiding);
        bndList.setAll(i * 32, cs[i].binding);
      }
    }
    return (ids, hid, bnd);
  }

  /// Round 2: this participant's 32-byte signature share. [commitments] is the
  /// full round-1 set from every participating signer (including self).
  Uint8List frostSign(int identifier, Uint8List shareSecret, Uint8List groupPublicKey,
      FrostNonces nonces, Uint8List msg, List<FrostCommitment> commitments) {
    final ps = _toNative(shareSecret), pg = _toNative(groupPublicKey);
    final ph = _toNative(nonces.hiding), pbn = _toNative(nonces.binding), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Uint16, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, int)>('cryptolib_frost_sign')(
          identifier, ps, shareSecret.length, pg, groupPublicKey.length,
          ph, nonces.hiding.length, pbn, nonces.binding.length, pm, msg.length,
          ids, hid, bnd, commitments.length));
    } finally {
      for (final p in [ps, pg, ph, pbn, pm]) { if (p != nullptr) calloc.free(p); }
      calloc.free(ids); calloc.free(hid); calloc.free(bnd);
    }
  }

  /// Aggregate signature shares into one 64-byte Ed25519 signature.
  Uint8List frostAggregate(Uint8List groupPublicKey, Uint8List msg,
      List<FrostCommitment> commitments, List<Uint8List> sigShares) {
    final pg = _toNative(groupPublicKey), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    final flat = Uint8List(sigShares.length * 32);
    for (var i = 0; i < sigShares.length; i++) { flat.setAll(i * 32, sigShares[i]); }
    final pf = _toNative(flat);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>)>('cryptolib_frost_aggregate')(
          pg, groupPublicKey.length, pm, msg.length, ids, hid, bnd, commitments.length, pf));
    } finally {
      if (pg != nullptr) calloc.free(pg);
      if (pm != nullptr) calloc.free(pm);
      if (pf != nullptr) calloc.free(pf);
      calloc.free(ids); calloc.free(hid); calloc.free(bnd);
    }
  }

  /// Verify an aggregate signature with standard Ed25519.
  bool frostVerify(Uint8List msg, Uint8List sig, Uint8List groupPublicKey) {
    final pm = _toNative(msg), psig = _toNative(sig), pg = _toNative(groupPublicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_frost_verify')(
          pm, msg.length, psig, sig.length, pg, groupPublicKey.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (psig != nullptr) calloc.free(psig);
      if (pg != nullptr) calloc.free(pg);
    }
  }

  /// Verify one participant's signature share against its public share.
  bool frostVerifyShare(int identifier, Uint8List publicShare, Uint8List sigShare,
      FrostCommitment commitment, Uint8List groupPublicKey, Uint8List msg,
      List<FrostCommitment> commitments) {
    final pp = _toNative(publicShare), pss = _toNative(sigShare);
    final pch = _toNative(commitment.hiding), pcb = _toNative(commitment.binding);
    final pg = _toNative(groupPublicKey), pm = _toNative(msg);
    final (ids, hid, bnd) = _frostBufs(commitments);
    try {
      return _lib.lookupFunction<
          Int32 Function(Uint16, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, Size),
          int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint16>, Pointer<Uint8>, Pointer<Uint8>, int)>('cryptolib_frost_verify_share')(
          identifier, pp, publicShare.length, pss, sigShare.length,
          pch, commitment.hiding.length, pcb, commitment.binding.length,
          pg, groupPublicKey.length, pm, msg.length, ids, hid, bnd, commitments.length) == 1;
    } finally {
      for (final p in [pp, pss, pch, pcb, pg, pm]) { if (p != nullptr) calloc.free(p); }
      calloc.free(ids); calloc.free(hid); calloc.free(bnd);
    }
  }

  // ── HPKE — Hybrid Public Key Encryption (RFC 9180) ─────────────────────────
  /// Fresh X25519 key pair for HPKE.
  KeyPairResult hpkeKeygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>('cryptolib_hpke_keygen')());

  /// Deterministic DHKEM(X25519).DeriveKeyPair from input keying material.
  KeyPairResult hpkeDeriveKeyPair(Uint8List ikm) {
    final p = _toNative(ikm);
    try {
      return _extractKeyPair(_lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int)>('cryptolib_hpke_derive_keypair')(p, ikm.length));
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Sender key schedule (any mode). Returns the KEM encapsulation + context.
  HpkeSender hpkeSetupS(int kdf, int aead, int mode, Uint8List recipientPublic, Uint8List info,
      {Uint8List? psk, Uint8List? pskId, Uint8List? senderSecret}) {
    final ppk = _toNative(recipientPublic), pinfo = _toNative(info);
    final ppsk = psk != null ? _toNative(psk) : nullptr;
    final ppid = pskId != null ? _toNative(pskId) : nullptr;
    final psks = senderSecret != null ? _toNative(senderSecret) : nullptr;
    final encOut = calloc<CryptoBuffer>();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Int32, Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<CryptoBuffer>, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, int, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<CryptoBuffer>, Pointer<Pointer<Utf8>>)>('cryptolib_hpke_setup_s')(
          kdf, aead, mode, ppk, recipientPublic.length, pinfo, info.length,
          ppsk, psk?.length ?? 0, ppid, pskId?.length ?? 0, psks, senderSecret?.length ?? 0, encOut, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: hpke setup_s failed');
      final enc = _copyBuf(encOut.ref); // copies + frees the buffer
      return HpkeSender(enc, HpkeContext(this, h));
    } finally {
      for (final p in [ppk, pinfo, ppsk, ppid, psks]) { if (p != nullptr) calloc.free(p); }
      calloc.free(encOut); calloc.free(errPtr);
    }
  }

  /// Receiver key schedule (any mode). Returns the established context.
  HpkeContext hpkeSetupR(int kdf, int aead, int mode, Uint8List enc, Uint8List recipientSecret, Uint8List info,
      {Uint8List? psk, Uint8List? pskId, Uint8List? senderPublic}) {
    final pe = _toNative(enc), psk_ = _toNative(recipientSecret), pinfo = _toNative(info);
    final ppsk = psk != null ? _toNative(psk) : nullptr;
    final ppid = pskId != null ? _toNative(pskId) : nullptr;
    final pks = senderPublic != null ? _toNative(senderPublic) : nullptr;
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Int32, Int32, Int32, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size,
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(int, int, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_hpke_setup_r')(
          kdf, aead, mode, pe, enc.length, psk_, recipientSecret.length, pinfo, info.length,
          ppsk, psk?.length ?? 0, ppid, pskId?.length ?? 0, pks, senderPublic?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) { final m = errPtr.value.toDartString(); _strFree(errPtr.value); throw Exception(m); }
      if (h == nullptr) throw Exception('cryptolib: hpke setup_r failed');
      return HpkeContext(this, h);
    } finally {
      for (final p in [pe, psk_, pinfo, ppsk, ppid, pks]) { if (p != nullptr) calloc.free(p); }
      calloc.free(errPtr);
    }
  }

  /// Single-shot base-mode encryption → (enc, ciphertext).
  (Uint8List, Uint8List) hpkeSealBase(int kdf, int aead, Uint8List recipientPublic, Uint8List info,
      Uint8List plaintext, {Uint8List? aad}) {
    final s = hpkeSetupS(kdf, aead, 0, recipientPublic, info);
    try { return (s.enc, s.context.seal(plaintext, aad: aad)); } finally { s.context.close(); }
  }

  /// Single-shot base-mode decryption.
  Uint8List hpkeOpenBase(int kdf, int aead, Uint8List enc, Uint8List recipientSecret, Uint8List info,
      Uint8List ciphertext, {Uint8List? aad}) {
    final r = hpkeSetupR(kdf, aead, 0, enc, recipientSecret, info);
    try { return r.open(ciphertext, aad: aad); } finally { r.close(); }
  }

  Uint8List _hpkeMsg(String symbol, Pointer<Void> h, Uint8List data, Uint8List? aad) {
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    final pd = _toNative(data);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(symbol)(
          h, pa, aad?.length ?? 0, pd, data.length));
    } finally { if (pa != nullptr) calloc.free(pa); if (pd != nullptr) calloc.free(pd); }
  }

  Uint8List _hpkeExport(Pointer<Void> h, Uint8List exporterContext, int length) {
    final pc = exporterContext.isNotEmpty ? _toNative(exporterContext) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int, int)>('cryptolib_hpke_export')(
          h, pc, exporterContext.length, length));
    } finally { if (pc != nullptr) calloc.free(pc); }
  }

  void _hpkeFree(Pointer<Void> h) => _lib.lookupFunction<
      Void Function(Pointer<Void>), void Function(Pointer<Void>)>('cryptolib_hpke_context_free')(h);
}

/// HPKE (RFC 9180) ciphersuite selectors.
class HpkeKdf { static const int sha256 = 1; static const int sha512 = 3; }
class HpkeAead {
  static const int aes128Gcm = 1;
  static const int aes256Gcm = 2;
  static const int chaCha20Poly1305 = 3;
  static const int exportOnly = 0xFFFF;
}
class HpkeMode { static const int base = 0; static const int psk = 1; static const int auth = 2; static const int authPsk = 3; }

/// An established one-directional HPKE context. Stateful; close() when done.
class HpkeContext {
  final CryptoLib _cl;
  Pointer<Void> _h;
  HpkeContext(this._cl, this._h);

  /// Sender: AEAD-seal the next message (advances the sequence).
  Uint8List seal(Uint8List plaintext, {Uint8List? aad}) => _cl._hpkeMsg('cryptolib_hpke_seal', _h, plaintext, aad);

  /// Receiver: AEAD-open the next message (advances the sequence).
  Uint8List open(Uint8List ciphertext, {Uint8List? aad}) => _cl._hpkeMsg('cryptolib_hpke_open', _h, ciphertext, aad);

  /// Derive a length-byte secret bound to this context (RFC 9180 §5.3).
  Uint8List export(Uint8List exporterContext, int length) => _cl._hpkeExport(_h, exporterContext, length);

  void close() { if (_h != nullptr) { _cl._hpkeFree(_h); _h = nullptr; } }
}

/// Sender-side HPKE result: the KEM encapsulation plus the sender context.
class HpkeSender {
  final Uint8List enc;
  final HpkeContext context;
  HpkeSender(this.enc, this.context);
}

/// A post-quantum forward-secret ratchet channel (hybrid KEM Double Ratchet).
/// Stateful — not safe for concurrent use; close() when done.
class Session {
  final CryptoLib _cl;
  Pointer<Void> _h;
  Session(this._cl, this._h);

  /// The handshake message to send to the responder (acceptSession). Empty on a responder.
  Uint8List handshake() => _cl._sessionHandshake(_h);

  /// Encrypt the next outgoing message (advances the sending ratchet).
  Uint8List encrypt(Uint8List plaintext, {Uint8List? aad}) =>
      _cl._sessionMsg('cryptolib_session_encrypt', _h, plaintext, aad);

  /// Decrypt an incoming message (handles ratchet turns + out-of-order; transactional).
  Uint8List decrypt(Uint8List message, {Uint8List? aad}) =>
      _cl._sessionMsg('cryptolib_session_decrypt', _h, message, aad);

  void close() { if (_h != nullptr) { _cl._sessionFree(_h); _h = nullptr; } }
}

/// FROST trusted-dealer output: the group public key plus per-participant
/// shares. Share i (0-based) has FROST identifier i+1. Keep [secretShares]
/// private; distribute one to each participant.
class FrostKeyGen {
  final Uint8List groupPublicKey;
  final List<Uint8List> secretShares; // n × 32 B (secret scalars)
  final List<Uint8List> publicShares; // n × 32 B (points, for verifyShare)
  FrostKeyGen(this.groupPublicKey, this.secretShares, this.publicShares);
}

/// A participant's public round-1 commitment.
class FrostCommitment {
  final int identifier;
  final Uint8List hiding;  // 32 B point
  final Uint8List binding; // 32 B point
  FrostCommitment(this.identifier, this.hiding, this.binding);
}

/// A participant's secret round-1 nonces (never share these).
class FrostNonces {
  final Uint8List hiding;  // 32 B scalar
  final Uint8List binding; // 32 B scalar
  FrostNonces(this.hiding, this.binding);
}

/// Assurance tier for Flagship/Fortress sealed messaging (index 0 / 1).
enum SealedTier { flagship, fortress }

/// Public metadata carried by a sealed envelope (no secrets).
class SealedInfo {
  final int version;
  final int suite; // 1 = Flagship, 2 = Fortress
  final bool streaming;
  final Uint8List fingerprint; // BLAKE2b-128 of the recipient public key
  final int kemCiphertextLen;
  SealedInfo({required this.version, required this.suite, required this.streaming,
      required this.fingerprint, required this.kemCiphertextLen});
}

/// A party's keypairs — recipient (KEM) for receiving, sender (signature) for
/// signing. The config/setup handle for the sealed-messaging API.
class Identity {
  final CryptoLib lib;
  final SealedTier tier;
  final Uint8List recipientPublic, recipientSecret, senderPublic, senderSecret;
  Identity(this.lib, this.tier, this.recipientPublic, this.recipientSecret,
      this.senderPublic, this.senderSecret);

  Uint8List seal(Uint8List plaintext, Uint8List recipientPublic, {Uint8List? aad, Uint8List? purpose}) =>
      lib.sealedSeal(tier, plaintext, recipientPublic, senderSecret, aad: aad, purpose: purpose);
  Uint8List open(Uint8List envelope, Uint8List senderPublic, {Uint8List? aad, Uint8List? purpose}) =>
      lib.sealedOpen(tier, envelope, recipientSecret, recipientPublic, senderPublic, aad: aad, purpose: purpose);
  SealedStreamSealer newStreamSealer(Uint8List recipientPublic, {Uint8List? purpose}) =>
      lib.sealedSealerBegin(tier, recipientPublic, senderSecret, purpose: purpose);
  SealedStreamOpener newStreamOpener(Uint8List preamble, Uint8List senderPublic, {Uint8List? purpose}) =>
      lib.sealedOpenerBegin(tier, preamble, recipientSecret, recipientPublic, senderPublic, purpose: purpose);
}

/// Encrypting stream: preamble() once, push() each chunk, finalize() for the last
/// chunk + signed trailer; close() when done.
class SealedStreamSealer {
  final CryptoLib _cl;
  Pointer<Void> _h;
  SealedStreamSealer(this._cl, this._h);
  Uint8List preamble() => _cl._sealedSealerPreamble(_h);
  Uint8List push(Uint8List chunk) => _cl._sealedSealerPush(_h, chunk);
  (Uint8List ciphertext, Uint8List trailer) finalize([Uint8List? last]) => _cl._sealedSealerFinalize(_h, last);
  void close() { if (_h != nullptr) { _cl._sealedSealerFree(_h); _h = nullptr; } }
}

/// Decrypting stream: pull() each chunk (isFinal on the last), then finalize()
/// to verify the sender signature over the whole stream.
class SealedStreamOpener {
  final CryptoLib _cl;
  Pointer<Void> _h;
  SealedStreamOpener(this._cl, this._h);
  (Uint8List plaintext, bool isFinal) pull(Uint8List ct) => _cl._sealedOpenerPull(_h, ct);
  void finalize(Uint8List trailer) => _cl._sealedOpenerFinalize(_h, trailer);
  void close() { if (_h != nullptr) { _cl._sealedOpenerFree(_h); _h = nullptr; } }
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
