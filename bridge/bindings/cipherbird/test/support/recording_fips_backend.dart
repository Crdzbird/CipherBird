import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';

/// A backend that records calls and returns zero-filled outputs.
final class RecordingFipsBackend implements FipsBackend {
  RecordingFipsBackend();

  /// Every call, in order.
  final calls = <String>[];

  Uint8List _rec(String call, int n) {
    calls.add(call);
    return Uint8List(n);
  }

  @override
  Future<FipsModuleInfo> module() async =>
      const FipsModuleInfo(module: 'fake', platform: 'test');

  @override
  Future<Uint8List> digest(FipsHash hash, Uint8List data) async =>
      _rec('digest:${hash.name}:${data.length}', 32);

  @override
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) async =>
      _rec('hmac:${key.length}', 32);

  @override
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) async => _rec('hkdf:$count:${salt?.length}:${info?.length}', count);

  @override
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) async => _rec('pbkdf2:$iterations:$count', count);

  @override
  Future<Uint8List> random(int count) async => Uint8List(count);

  @override
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) async => Uint8List(28 + plaintext.length);

  @override
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) async => Uint8List(wire.length - 28);

  @override
  Future<KeyPairResult> p256Keygen() async =>
      KeyPairResult(publicKey: Uint8List(65), secretKey: Uint8List(32));

  @override
  Future<Uint8List> p256Ecdh(
    Uint8List privateKey,
    Uint8List peerPublic,
  ) async => Uint8List(32);

  @override
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) async =>
      Uint8List(70);

  @override
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) async => true;
}
