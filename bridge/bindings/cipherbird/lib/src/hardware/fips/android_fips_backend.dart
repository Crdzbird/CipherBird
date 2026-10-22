import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';
import 'package:cipherbird/src/hardware/fips/android_fips_channel.dart';
import 'package:flutter/services.dart';

/// The Android platform providers through the plugin method channel.
final class AndroidFipsBackend implements FipsBackend {
  const AndroidFipsBackend();

  @override
  Future<FipsModuleInfo> module() => AndroidFipsChannel.module();

  @override
  Future<Uint8List> digest(FipsHash hash, Uint8List data) =>
      AndroidFipsChannel.bytes('digest', {'hash': hash.value, 'data': data});

  @override
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) =>
      AndroidFipsChannel.bytes('hmac', {
        'hash': hash.value,
        'key': key,
        'data': data,
      });

  @override
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) => AndroidFipsChannel.hkdf(hash, ikm, salt, info, count);

  @override
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) => AndroidFipsChannel.pbkdf2(hash, password, salt, iterations, count);

  @override
  Future<Uint8List> random(int count) =>
      AndroidFipsChannel.bytes('random', {'count': count});

  @override
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) => AndroidFipsChannel.bytes('aesGcmEncrypt', {
    'key': key,
    'plaintext': plaintext,
    'aad': aad,
  });

  @override
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) => AndroidFipsChannel.bytes('aesGcmDecrypt', {
    'key': key,
    'wire': wire,
    'aad': aad,
  });

  @override
  Future<KeyPairResult> p256Keygen() =>
      AndroidFipsChannel.keyPair('p256Keygen');

  @override
  Future<Uint8List> p256Ecdh(Uint8List privateKey, Uint8List peerPublic) =>
      AndroidFipsChannel.bytes('p256Ecdh', {
        'privateKey': privateKey,
        'peerPublic': peerPublic,
      });

  @override
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) =>
      AndroidFipsChannel.bytes('p256Sign', {
        'privateKey': privateKey,
        'message': message,
      });

  @override
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) => AndroidFipsChannel.call<bool>('p256Verify', {
    'publicKey': publicKey,
    'message': message,
    'signature': signature,
  });
}
