import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/fips_backend_native.dart'
    if (dart.library.js_interop) 'package:cipherbird/src/hardware/fips/fips_backend_web.dart';
import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';

/// Approved operations routed through the validated module of the platform
/// the app runs on: Apple corecrypto (CryptoKit) on iOS and macOS, the
/// Android platform providers (Conscrypt, BoringCrypto) on Android, and the
/// OpenSSL FIPS Provider (CMVP #4985) when the engine is the fips profile.
/// Every call may throw a `FipsException`; [module] says what served it.
final class DeviceFips {
  const DeviceFips._(this._backend);

  /// The module for this platform. [backend] overrides it, for tests.
  factory DeviceFips.platform({FipsBackend? backend, CipherBird? engine}) =>
      DeviceFips._(backend ?? createPlatformFipsBackend(engine: engine));

  final FipsBackend _backend;

  /// What performs the operations.
  Future<FipsModuleInfo> module() => _backend.module();

  /// Digest of [data].
  Future<Uint8List> digest(FipsHash hash, Uint8List data) =>
      _backend.digest(hash, data);

  /// HMAC of [data] under [key] (at least 14 bytes).
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) =>
      _backend.hmac(hash, key, data);

  /// HKDF extract-and-expand to [count] bytes.
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm, {
    required int count,
    Uint8List? salt,
    Uint8List? info,
  }) => _backend.hkdf(hash, ikm, salt, info, count);

  /// PBKDF2: [salt] at least 16 bytes, [iterations] at least 1000.
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt, {
    int iterations = 600000,
    int count = 32,
  }) => _backend.pbkdf2(hash, password, salt, iterations, count);

  /// [count] bytes from the module's DRBG.
  Future<Uint8List> random(int count) => _backend.random(count);

  /// AES-256-GCM: nonce(12) | ciphertext | tag(16), nonce from the module.
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext, {
    Uint8List? aad,
  }) => _backend.aesGcmEncrypt(key, plaintext, aad);

  /// AES-256-GCM open; any failure is `authentication_failed`.
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire, {
    Uint8List? aad,
  }) => _backend.aesGcmDecrypt(key, wire, aad);

  /// A fresh P-256 key pair: 65-byte public point, 32-byte scalar.
  Future<KeyPairResult> p256Keygen() => _backend.p256Keygen();

  /// ECDH shared secret (32 bytes).
  Future<Uint8List> p256Ecdh(Uint8List privateKey, Uint8List peerPublic) =>
      _backend.p256Ecdh(privateKey, peerPublic);

  /// ECDSA with SHA-256, DER signature.
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) =>
      _backend.p256Sign(privateKey, message);

  /// ECDSA verification.
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) => _backend.p256Verify(publicKey, message, signature);
}
