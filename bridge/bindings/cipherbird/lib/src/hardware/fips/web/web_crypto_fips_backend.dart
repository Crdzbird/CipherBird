import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_backend.dart';
import 'package:cipherbird/src/hardware/fips/fips_module_info.dart';
import 'package:cipherbird/src/hardware/fips/web/p256_keys.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle_keys.dart';
import 'package:cipherbird/src/hardware/fips/web/web_crypto_aead.dart';
import 'package:cipherbird/src/hardware/fips/web/web_crypto_derive.dart';
import 'package:cipherbird/src/hardware/fips/web/web_crypto_module.dart';
import 'package:cipherbird/src/hardware/fips/web/web_crypto_p256.dart';

/// The browser's own crypto behind the device facade: WebCrypto, which
/// Chromium backs with BoringSSL and Safari with CoreCrypto. It is the
/// platform's crypto, not a validated module as exposed to pages, and
/// [module] says so. Formats match the other backends.
final class WebCryptoFipsBackend implements FipsBackend {
  const WebCryptoFipsBackend();

  static const _subtle = Subtle();
  static const _keys = SubtleKeys(_subtle);
  static const _derive = WebCryptoDerive(_subtle, _keys);
  static const _aead = WebCryptoAead(_subtle, _keys);
  static const _p256 = WebCryptoP256(_subtle, P256Keys(_keys));

  @override
  Future<FipsModuleInfo> module() async => const WebCryptoModule().describe();

  @override
  Future<Uint8List> digest(FipsHash hash, Uint8List data) =>
      _derive.digest(hash, data);

  @override
  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) =>
      _derive.hmac(hash, key, data);

  @override
  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) => _derive.hkdf(hash, ikm, salt, info, count);

  @override
  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) => _derive.pbkdf2(hash, password, salt, iterations, count);

  @override
  Future<Uint8List> random(int count) async => _subtle.random(count);

  @override
  Future<Uint8List> aesGcmEncrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) => _aead.encrypt(key, plaintext, aad);

  @override
  Future<Uint8List> aesGcmDecrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) => _aead.decrypt(key, wire, aad);

  @override
  Future<KeyPairResult> p256Keygen() => _p256.keygen();

  @override
  Future<Uint8List> p256Ecdh(Uint8List privateKey, Uint8List peerPublic) =>
      _p256.ecdh(privateKey, peerPublic);

  @override
  Future<Uint8List> p256Sign(Uint8List privateKey, Uint8List message) =>
      _p256.sign(privateKey, message);

  @override
  Future<bool> p256Verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) => _p256.verify(publicKey, message, signature);
}
