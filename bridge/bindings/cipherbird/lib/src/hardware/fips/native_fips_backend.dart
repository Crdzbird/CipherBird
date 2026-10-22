import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird/src/hardware/fips/native_fips_info.dart';

/// The OpenSSL FIPS Provider inside a fips-profile engine.
final class NativeFipsBackend implements FipsBackend {
  NativeFipsBackend(this._engine) {
    NativeFipsInfo.require(_engine);
  }

  final CipherBird _engine;

  @override
  Future<FipsModuleInfo> module() async => NativeFipsInfo.of(_engine);

  @override
  Future<Uint8List> digest(FipsHash hash, Uint8List data) =>
      NativeFipsInfo.guard(() => _engine.fipsDigest(hash, data));

  @override
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) =>
      NativeFipsInfo.guard(() => _engine.fipsHmac(hash, key, data));

  @override
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) => NativeFipsInfo.guard(
    () => _engine.fipsHkdf(hash, ikm, count, salt: salt, info: info),
  );

  @override
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) => NativeFipsInfo.guard(
    () => _engine.fipsPbkdf2(
      hash,
      password,
      salt,
      iterations: iterations,
      outLen: count,
    ),
  );

  @override
  Future<Uint8List> random(int count) =>
      NativeFipsInfo.guard(() => _engine.fipsRandom(count));

  @override
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) => NativeFipsInfo.guard(
    () => _engine.fipsAesGcmEncrypt(key, plaintext, aad: aad),
  );

  @override
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) => NativeFipsInfo.guard(
    () => _engine.fipsAesGcmDecrypt(key, wire, aad: aad),
  );

  @override
  Future<KeyPairResult> p256Keygen() =>
      NativeFipsInfo.guard(_engine.fipsP256Keygen);

  @override
  Future<Uint8List> p256Ecdh(Uint8List privateKey, Uint8List peerPublic) =>
      NativeFipsInfo.guard(() => _engine.fipsP256Ecdh(privateKey, peerPublic));

  @override
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) =>
      NativeFipsInfo.guard(() => _engine.fipsP256Sign(privateKey, message));

  @override
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) => NativeFipsInfo.guard(
    () => _engine.fipsP256Verify(publicKey, message, signature),
  );
}
