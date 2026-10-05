/// CryptoLib for Dart/Flutter — an idiomatic dart:ffi wrapper around the
/// CryptoLib C ABI (libcryptolib_c).
///
/// The native library is bundled per platform (iOS/macOS via the Swift Package,
/// Android via jniLibs) and resolved automatically; no path or setup is needed.
///
/// ```dart
/// // Optional warm-up off the UI isolate (fire-and-forget):
/// CryptoLib.preload();
/// // Synchronous API — no await required:
/// final digest = CryptoLib.instance.sha256(utf8.encode('abc'));
/// ```
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

// Raw FFI layer (structs + native signatures) — kept separate from the API.
part 'ffi/structs.dart';
part 'ffi/typedefs.dart';
// Public result/value types.
part 'models.dart';
part 'enums.dart';
part 'facade.dart';
part 'security.dart';
part 'easy.dart';
// Small encoding helpers.
part 'utils.dart';
// High-level API, grouped by domain (extensions on CryptoLib).
part 'api/core.dart';
part 'api/hashing.dart';
part 'api/symmetric.dart';
part 'api/asymmetric.dart';
part 'api/vault.dart';
part 'api/keyring.dart';
part 'api/post_quantum.dart';
part 'api/bls.dart';
part 'api/asymmetric_vault.dart';
part 'api/entropy.dart';
part 'api/steganography.dart';
part 'api/evm_btc.dart';
part 'api/molecular_vault.dart';
part 'api/suite.dart';
part 'api/sealed.dart';
part 'api/session.dart';
part 'api/frost.dart';
part 'api/hpke.dart';
part 'api/ecvrf.dart';
part 'api/bbs.dart';
part 'api/oprf.dart';
part 'api/opaque.dart';
part 'api/rng.dart';
part 'api/composed.dart';
part 'api/noise.dart';

class CryptoLib {
  final DynamicLibrary _lib;

  // -- Cached function lookups --
  late final _InitDart _init;
  late final _VersionDart _version;
  late final _RandomBytesDart _randomBytes;
  late final _SecureEqualDart _secureEqual;

  // Memory free. Struct-level frees (keypair/bundle/packet/...) are intentionally
  // not bound: _copyBuf frees each CryptoBuffer individually, so calling them
  // would double-free.
  late final _BufferFreeDart _bufferFree;
  late final _StrFreeDart _strFree;

  // Hashing
  late final _Blake2bDart _blake2b;
  late final _Sha256Dart _sha256;
  late final _Sha512Dart _sha512;
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

    // Hashing
    _blake2b = _lib.lookupFunction<_Blake2bC, _Blake2bDart>('cryptolib_blake2b');
    _sha256 = _lib.lookupFunction<_Sha256C, _Sha256Dart>('cryptolib_sha256');
    _sha512 = _lib.lookupFunction<_Sha512C, _Sha512Dart>('cryptolib_sha512');
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

  /// Load the native library.
  ///
  /// Pass an explicit [path] to dlopen a specific file (desktop development).
  /// With no path, the platform default is used:
  ///   • iOS     → process image (static archive from the embedded
  ///               CryptoLib.xcframework is linked into the app binary)
  ///   • Android → libcryptolib_c.so (bundled in the per-ABI jniLibs folder)
  ///   • macOS   → libcryptolib_c.dylib (on the loader path)
  ///   • Linux   → libcryptolib_c.so
  factory CryptoLib.load([String? path]) {
    final resolved = (path != null && path.isNotEmpty)
        ? path
        // Dev/test override: point at any libcryptolib_c on disk.
        : Platform.environment['CRYPTOLIB_DYLIB'];
    final DynamicLibrary lib;
    if (resolved != null && resolved.isNotEmpty) {
      lib = DynamicLibrary.open(resolved);
    } else if (Platform.isIOS || Platform.isMacOS) {
      // iOS & macOS: the native library ships as an embedded dynamic framework
      // (CryptoLibC) via the plugin's Swift Package; its symbols are loaded
      // into the process at launch, so resolve them from the process itself.
      lib = DynamicLibrary.process();
    } else if (Platform.isAndroid || Platform.isLinux) {
      lib = DynamicLibrary.open('libcryptolib_c.so');
    } else {
      lib = DynamicLibrary.process();
    }
    return CryptoLib._(lib);
  }

  // ── Preload + lazy synchronous singleton ───────────────────────────────────
  //
  // The native library is loaded and initialized lazily on first use of
  // [instance] — fully synchronous, so crypto calls never require `await`.
  // [preload] is an OPTIONAL warm-up that does the one-time heavy work (mapping
  // the shared library + libsodium init) on a background isolate, so the first
  // call on the UI isolate is effectively free. Calling preload is not
  // required, and the API works identically whether or not you call it.

  static CryptoLib? _singleton;
  static bool _initialized = false;

  /// Process-wide instance. On first access the native library is opened and
  /// initialized **synchronously** (no `await`). If [preload] ran first, the OS
  /// has already mapped the library and libsodium is already initialized, so
  /// this is effectively instantaneous.
  static CryptoLib get instance {
    final s = _singleton ??= CryptoLib.load();
    if (!_initialized) {
      s.init(); // cryptolib_init is idempotent → safe even if preload ran it.
      _initialized = true;
    }
    return s;
  }

  /// Optionally warm the native library off the UI isolate.
  ///
  /// Spawns a short-lived background isolate that opens the shared library
  /// (mapping it into the process / OS loader cache) and runs the one-time
  /// libsodium initialization. Because dlopen mapping and libsodium init are
  /// process-global, this warms the path for the main isolate's later
  /// synchronous [instance] access.
  ///
  /// Call it once near app start (e.g. in `main()`); the returned Future is
  /// fire-and-forget — you may ignore it or `await` it, but the crypto API
  /// ([instance]) never requires awaiting it. Safe to call multiple times and
  /// safe to never call.
  ///
  /// Returns true if the warm-up completed, false if it failed (in which case
  /// the lazy synchronous path still works on first real use).
  static Future<bool> preload() async {
    try {
      return await Isolate.run<bool>(() {
        // Fresh isolate. DynamicLibrary handles are per-isolate, but the dlopen
        // mapping and libsodium init they trigger are process-global.
        final warm = CryptoLib.load();
        warm.init();
        // Touch a trivial symbol so lazy lookups resolve here too.
        warm.version();
        return true;
      });
    } on Object catch (_) {
      return false;
    }
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

  /// Marshal a list of byte buffers into the C `const uint8_t* const*` +
  /// `const size_t*` array pair. Release both (and the element buffers) with
  /// [_freeNativeList].
  (Pointer<Pointer<Uint8>>, Pointer<Size>) _toNativeList(List<Uint8List> items) {
    final n = items.length;
    final ptrs = calloc<Pointer<Uint8>>(n);
    final lens = calloc<Size>(n);
    for (var i = 0; i < n; i++) {
      final b = items[i];
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
}
