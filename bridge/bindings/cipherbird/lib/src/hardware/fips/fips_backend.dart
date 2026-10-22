import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';

/// The validated module behind the device FIPS facade. Every call may
/// throw a `FipsException`. Hash ids follow [FipsHash].
abstract interface class FipsBackend {
  /// What performs the operations.
  Future<FipsModuleInfo> module();

  /// Digest of [data].
  Future<Uint8List> digest(FipsHash hash, Uint8List data);

  /// HMAC of [data] under [key] (at least 14 bytes).
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data);

  /// HKDF extract-and-expand to [count] bytes.
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  );

  /// PBKDF2: [salt] at least 16 bytes, [iterations] at least 1000.
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  );

  /// [count] bytes from the module DRBG.
  Future<Uint8List> random(int count);

  /// AES-256-GCM with a module-generated nonce: nonce(12) | ciphertext | tag(16).
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  );

  /// AES-256-GCM open; any failure is `authentication_failed`.
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  );

  /// A fresh P-256 key pair: 65-byte public point, 32-byte scalar.
  Future<KeyPairResult> p256Keygen();

  /// ECDH shared secret (32 bytes).
  Future<Uint8List> p256Ecdh(Uint8List privateKey, Uint8List peerPublic);

  /// ECDSA with SHA-256, DER signature.
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message);

  /// ECDSA verification.
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  );
}
