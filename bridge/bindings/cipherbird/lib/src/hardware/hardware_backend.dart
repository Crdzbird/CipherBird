import 'dart:typed_data';

import 'package:cipherbird/src/hardware/hardware_attestation.dart';
import 'package:cipherbird/src/hardware/hardware_backing.dart';

/// The platform key module behind a hardware key. Every call may throw a
/// `HardwareKeyException`.
abstract interface class HardwareBackend {
  /// Creates the key for [label]; returns where it landed.
  Future<HardwareBacking> create(String label, {required bool biometric});

  /// Whether a key named [label] exists.
  Future<bool> exists(String label);

  /// Removes the key for [label] and its attestation key.
  Future<void> delete(String label);

  /// Where the key for [label] lives.
  Future<HardwareBacking> backing(String label);

  /// Wraps [input] under the key for [label]; no user interaction.
  Future<Uint8List> wrap(String label, Uint8List input);

  /// Unwraps [blob] with the key for [label]; a biometric-gated key shows
  /// the system prompt with [reason].
  Future<Uint8List> unwrap(
    String label,
    Uint8List blob, {
    required String reason,
  });

  /// Attests the key for [label] against [challenge].
  Future<HardwareAttestation> attest(String label, Uint8List challenge);
}
