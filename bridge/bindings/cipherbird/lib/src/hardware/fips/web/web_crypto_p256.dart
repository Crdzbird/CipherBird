import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/web/ecdsa_der.dart';
import 'package:cipherbird/src/hardware/fips/web/js_value.dart';
import 'package:cipherbird/src/hardware/fips/web/p256_keys.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle.dart';

/// P-256 ECDH and ECDSA on WebCrypto, DER signatures as the other modules.
final class WebCryptoP256 {
  const WebCryptoP256(this._subtle, this._keys);

  final Subtle _subtle;
  final P256Keys _keys;
  static const _der = EcdsaDer();
  static const _ecdsa = {'name': 'ECDSA', 'hash': 'SHA-256'};

  Future<KeyPairResult> keygen() async {
    final (point, scalar) = await _keys.generate();
    return KeyPairResult(publicKey: point, secretKey: scalar);
  }

  Future<Uint8List> ecdh(Uint8List privateKey, Uint8List peerPublic) async {
    final mine = await _keys.private(privateKey, 'ECDH', 'deriveBits');
    final theirs = await _keys.public(peerPublic, 'ECDH', const []);
    return _subtle.deriveBits(
      {'name': 'ECDH', 'public': JsValue(theirs)},
      mine,
      256,
    );
  }

  Future<Uint8List> sign(Uint8List privateKey, Uint8List message) async {
    final k = await _keys.private(privateKey, 'ECDSA', 'sign');
    return _der.fromRaw(await _subtle.sign(_ecdsa, k, message));
  }

  Future<bool> verify(
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature,
  ) async {
    final k = await _keys.public(publicKey, 'ECDSA', const ['verify']);
    final Uint8List raw;
    try {
      raw = _der.toRaw(signature, 32);
    } on Object {
      return false;
    }
    return _subtle.verify(_ecdsa, k, raw, message);
  }
}
