import 'dart:convert';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/web/subtle_keys.dart';

/// P-256 keys as the device modules carry them (a 32-byte scalar and a
/// 65-byte point) imported into WebCrypto for ECDH or ECDSA.
final class P256Keys {
  const P256Keys(this._keys);

  final SubtleKeys _keys;

  /// PKCS#8 prefix for an ECPrivateKey on prime256v1 that carries only the
  /// scalar; the browser recomputes the public point.
  static const _pkcs8Prefix = [
    0x30,
    0x41,
    0x02,
    0x01,
    0x00,
    0x30,
    0x13,
    0x06,
    0x07,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    0x86,
    0x48,
    0xce,
    0x3d,
    0x03,
    0x01,
    0x07,
    0x04,
    0x27,
    0x30,
    0x25,
    0x02,
    0x01,
    0x01,
    0x04,
    0x20,
  ];

  Future<JSObject> private(Uint8List scalar, String algorithm, String usage) =>
      _keys.importRaw(
        Uint8List.fromList([..._pkcs8Prefix, ...scalar]),
        {'name': algorithm, 'namedCurve': 'P-256'},
        [usage],
        format: 'pkcs8',
      );

  Future<JSObject> public(
    Uint8List point,
    String algorithm,
    List<String> usages,
  ) => _keys.importRaw(point, {
    'name': algorithm,
    'namedCurve': 'P-256',
  }, usages);

  /// A fresh pair: the raw point and the scalar taken from its JWK.
  Future<(Uint8List, Uint8List)> generate() async {
    final pair = await _keys.generate(
      {'name': 'ECDH', 'namedCurve': 'P-256'},
      ['deriveBits'],
    );
    final jwk = await _keys.exportJwk(pair.getProperty('privateKey'.toJS));
    final point = await _keys.exportRaw(pair.getProperty('publicKey'.toJS));
    final d = jwk['d']! as String;
    return (point, Uint8List.fromList(base64Url.decode(_pad(d))));
  }

  static String _pad(String s) => s + '=' * ((4 - s.length % 4) % 4);
}
