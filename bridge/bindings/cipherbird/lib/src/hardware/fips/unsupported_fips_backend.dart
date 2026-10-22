import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_fips.dart';

/// A platform with no validated module reachable from this plugin: every
/// call throws `unsupported`.
final class UnsupportedFipsBackend implements FipsBackend {
  const UnsupportedFipsBackend(this.platform);

  /// The platform name, for the error message.
  final String platform;

  Never _fail() =>
      throw FipsException('unsupported', 'no validated module on $platform');

  @override
  Future<FipsModuleInfo> module() async => _fail();

  @override
  Future<Uint8List> digest(FipsHash hash, Uint8List data) async => _fail();

  @override
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) async =>
      _fail();

  @override
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) async => _fail();

  @override
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) async => _fail();

  @override
  Future<Uint8List> random(int count) async => _fail();

  @override
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) async => _fail();

  @override
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) async => _fail();

  @override
  Future<KeyPairResult> p256Keygen() async => _fail();

  @override
  Future<Uint8List> p256Ecdh(
    Uint8List privateKey,
    Uint8List peerPublic,
  ) async => _fail();

  @override
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) async =>
      _fail();

  @override
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) async => _fail();
}
