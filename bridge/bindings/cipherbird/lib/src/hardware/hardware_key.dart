import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/backend_native.dart'
    if (dart.library.js_interop) 'package:cipherbird/src/hardware/backend_web.dart';
import 'package:cipherbird/src/hardware/hardware_attestation.dart';
import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/hardware_backing.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';

/// A key held by the platform key module under a [label]. It wraps and
/// unwraps keyring factors; the key itself never leaves the module, and a
/// key created with [create] and `biometric: true` unwraps only after the
/// user passes the system biometric prompt.
final class HardwareKey {
  const HardwareKey._(this.label, this.backing, this._backend);

  /// Creates the key for [label]; throws `exists` if it is already there.
  /// [backend] overrides the platform module, for tests.
  static Future<HardwareKey> create(
    String label, {
    bool biometric = false,
    HardwareBackend? backend,
  }) async {
    final b = backend ?? createPlatformBackend();
    final backing = await b.create(label, biometric: biometric);
    return HardwareKey._(label, backing, b);
  }

  /// The existing key for [label]; throws `not_found` when absent.
  static Future<HardwareKey> open(
    String label, {
    HardwareBackend? backend,
  }) async {
    final b = backend ?? createPlatformBackend();
    if (!await b.exists(label)) {
      throw HardwareKeyException('not_found', 'no key named $label');
    }
    return HardwareKey._(label, await b.backing(label), b);
  }

  /// Whether a key named [label] exists.
  static Future<bool> exists(String label, {HardwareBackend? backend}) =>
      (backend ?? createPlatformBackend()).exists(label);

  /// The module name.
  final String label;

  /// Where the key lives.
  final HardwareBacking backing;

  final HardwareBackend _backend;

  /// The label as the keyring slot's key id.
  Uint8List get keyId => Uint8List.fromList(label.codeUnits);

  /// Wraps [secret]; the output is safe to store.
  Future<Uint8List> wrap(SecretBytes secret) =>
      _backend.wrap(label, secret.bytes);

  /// Unwraps [blob]; shows the biometric prompt with [reason] for gated keys.
  Future<SecretBytes> unwrap(
    Uint8List blob, {
    String reason = 'Unlock your keys',
  }) async =>
      SecretBytes.take(await _backend.unwrap(label, blob, reason: reason));

  /// Attests this key against [challenge] for a server.
  Future<HardwareAttestation> attest(Uint8List challenge) =>
      _backend.attest(label, challenge);

  /// Removes the key from the module. Slots it wrapped can no longer unlock.
  Future<void> delete() => _backend.delete(label);
}
