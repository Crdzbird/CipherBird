import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/fips_exception.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle.dart';
import 'package:cipherbird/src/hardware/fips/web/subtle_keys.dart';

/// AES-256-GCM on WebCrypto in the engine's wire layout: nonce(12),
/// ciphertext, tag(16).
final class WebCryptoAead {
  const WebCryptoAead(this._subtle, this._keys);

  final Subtle _subtle;
  final SubtleKeys _keys;

  Future<Uint8List> encrypt(
    Uint8List key,
    Uint8List plaintext,
    Uint8List? aad,
  ) async {
    final k = await _keys.importRaw(key, {'name': 'AES-GCM'}, ['encrypt']);
    final nonce = _subtle.random(12);
    final sealed = await _subtle.encrypt(_gcm(nonce, aad), k, plaintext);
    return Uint8List.fromList([...nonce, ...sealed]);
  }

  Future<Uint8List> decrypt(
    Uint8List key,
    Uint8List wire,
    Uint8List? aad,
  ) async {
    if (wire.length < 28) {
      throw const FipsException('authentication_failed', 'wire too short');
    }
    final k = await _keys.importRaw(key, {'name': 'AES-GCM'}, ['decrypt']);
    try {
      return await _subtle.decrypt(
        _gcm(wire.sublist(0, 12), aad),
        k,
        wire.sublist(12),
      );
    } on Object {
      throw const FipsException('authentication_failed', 'AES-GCM open failed');
    }
  }

  Map<String, Object?> _gcm(Uint8List nonce, Uint8List? aad) => {
    'name': 'AES-GCM',
    'iv': nonce,
    'tagLength': 128,
    if (aad != null && aad.isNotEmpty) 'additionalData': aad,
  };
}
