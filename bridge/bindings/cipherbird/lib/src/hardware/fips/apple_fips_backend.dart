import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_aead.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_call.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_derive.dart';
import 'package:cipherbird/src/hardware/fips/apple_fips_keys.dart';

/// Apple corecrypto through CryptoKit, CommonCrypto and Security, reached
/// through the plugin Swift functions.
final class AppleFipsBackend implements FipsBackend {
  const AppleFipsBackend();

  @override
  Future<FipsModuleInfo> module() async => AppleFipsDerive.module();

  @override
  Future<Uint8List> digest(FipsHash hash, Uint8List data) async =>
      AppleFipsCall.run([
        data,
      ], (b, i, o, l) => b.digest(hash.value, i[0], data.length, o, l));

  @override
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) async =>
      AppleFipsCall.run(
        [key, data],
        (b, i, o, l) =>
            b.hmac(hash.value, i[0], key.length, i[1], data.length, o, l),
      );

  @override
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) async => AppleFipsDerive.hkdf(hash, ikm, salt, info, count);

  @override
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) async => AppleFipsCall.run(
    [password, salt],
    (b, i, o, l) => b.pbkdf2(
      hash.value,
      i[0],
      password.length,
      i[1],
      salt.length,
      iterations,
      count,
      o,
      l,
    ),
  );

  @override
  Future<Uint8List> random(int count) async =>
      AppleFipsCall.run([], (b, _, o, l) => b.random(count, o, l));

  @override
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) async => AppleFipsAead.encrypt(key, plaintext, aad);

  @override
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) async => AppleFipsAead.decrypt(key, wire, aad);

  @override
  Future<KeyPairResult> p256Keygen() async => AppleFipsKeys.keygen();

  @override
  Future<Uint8List> p256Ecdh(
    Uint8List privateKey,
    Uint8List peerPublic,
  ) async => AppleFipsKeys.ecdh(privateKey, peerPublic);

  @override
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) async =>
      AppleFipsKeys.sign(privateKey, message);

  @override
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) async => AppleFipsKeys.verify(publicKey, message, signature);
}
