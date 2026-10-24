import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/web/subtle.dart';
import 'package:cipherbird/src/hardware/hardware_attestation.dart';
import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/hardware_backing.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';
import 'package:cipherbird/src/hardware/web/indexed_db_keys.dart';

/// The browser's key module: a non-extractable AES-256-GCM key made by
/// WebCrypto and kept in IndexedDB. Script on the origin can use the key
/// but never read its bytes, which is what a keyring slot at rest needs;
/// it is not a secure element and [HardwareBacking.browser] says so. There
/// is no biometric gate and no attestation.
final class WebKeyBackend implements HardwareBackend {
  const WebKeyBackend();

  static const _subtle = Subtle();
  static const _store = IndexedDbKeys();

  @override
  Future<HardwareBacking> create(
    String label, {
    required bool biometric,
  }) async {
    if (await exists(label)) {
      throw HardwareKeyException('exists', 'a key named $label exists');
    }
    final key = await _subtle.invoke('generateKey', [
      _subtle.alg({'name': 'AES-GCM', 'length': 256}),
      false.toJS,
      ['encrypt'.toJS, 'decrypt'.toJS].toJS,
    ]);
    await _store.put(label, key!);
    return HardwareBacking.browser;
  }

  @override
  Future<bool> exists(String label) async => await _store.get(label) != null;

  @override
  Future<void> delete(String label) => _store.delete(label);

  @override
  Future<HardwareBacking> backing(String label) async =>
      await exists(label) ? HardwareBacking.browser : HardwareBacking.none;

  Future<JSObject> _key(String label) async {
    final key = await _store.get(label);
    if (key == null) {
      throw HardwareKeyException('not_found', 'no key named $label');
    }
    return key as JSObject;
  }

  @override
  Future<Uint8List> wrap(String label, Uint8List input) async {
    final key = await _key(label);
    final nonce = _subtle.random(12);
    final sealed = await _subtle.encrypt(_gcm(nonce), key, input);
    return Uint8List.fromList([...nonce, ...sealed]);
  }

  @override
  Future<Uint8List> unwrap(
    String label,
    Uint8List blob, {
    required String reason,
  }) async {
    if (blob.length < 28) {
      throw const HardwareKeyException('failed', 'blob too short');
    }
    final key = await _key(label);
    try {
      return await _subtle.decrypt(
        _gcm(blob.sublist(0, 12)),
        key,
        blob.sublist(12),
      );
    } on Object {
      throw const HardwareKeyException('failed', 'the blob did not unwrap');
    }
  }

  Map<String, Object?> _gcm(Uint8List nonce) => {
    'name': 'AES-GCM',
    'iv': nonce,
    'tagLength': 128,
  };

  @override
  Future<HardwareAttestation> attest(String label, Uint8List challenge) async =>
      throw const HardwareKeyException(
        'unsupported',
        'a browser key has no attestation',
      );
}
