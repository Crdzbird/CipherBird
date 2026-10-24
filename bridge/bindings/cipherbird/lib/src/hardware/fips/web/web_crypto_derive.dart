import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/fips/fips_exception.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle_keys.dart';

/// Digests, HMAC, HKDF and PBKDF2 on WebCrypto.
final class WebCryptoDerive {
  const WebCryptoDerive(this._subtle, this._keys);

  final Subtle _subtle;
  final SubtleKeys _keys;

  static String hashName(FipsHash h) => switch (h) {
    FipsHash.sha256 => 'SHA-256',
    FipsHash.sha384 => 'SHA-384',
    FipsHash.sha512 => 'SHA-512',
    _ => throw FipsException('unsupported', 'WebCrypto has no ${h.name}'),
  };

  Future<Uint8List> digest(FipsHash hash, Uint8List data) =>
      _subtle.digest(hashName(hash), data);

  Future<Uint8List> hmac(FipsHash hash, Uint8List key, Uint8List data) async {
    final alg = {'name': 'HMAC', 'hash': hashName(hash)};
    final k = await _keys.importRaw(key, alg, ['sign']);
    return _subtle.sign({'name': 'HMAC'}, k, data);
  }

  Future<Uint8List> hkdf(
    FipsHash hash,
    Uint8List ikm,
    Uint8List? salt,
    Uint8List? info,
    int count,
  ) async {
    final k = await _keys.importRaw(ikm, {'name': 'HKDF'}, ['deriveBits']);
    final alg = {
      'name': 'HKDF',
      'hash': hashName(hash),
      'salt': salt ?? Uint8List(0),
      'info': info ?? Uint8List(0),
    };
    return _subtle.deriveBits(alg, k, count * 8);
  }

  Future<Uint8List> pbkdf2(
    FipsHash hash,
    Uint8List password,
    Uint8List salt,
    int iterations,
    int count,
  ) async {
    final k = await _keys.importRaw(
      password,
      {'name': 'PBKDF2'},
      [
        'deriveBits',
      ],
    );
    final alg = {
      'name': 'PBKDF2',
      'hash': hashName(hash),
      'salt': salt,
      'iterations': iterations,
    };
    return _subtle.deriveBits(alg, k, count * 8);
  }
}
