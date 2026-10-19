import 'dart:typed_data';

import 'package:cipherbird/src/hardware/hardware_attestation.dart';
import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/hardware_backing.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';

/// The backend on platforms without a key module: every call throws
/// `unsupported`, nothing falls back to a software key.
final class UnsupportedBackend implements HardwareBackend {
  const UnsupportedBackend(this.platform);

  /// The platform name for the error message.
  final String platform;

  Never _throw() => throw HardwareKeyException(
    'unsupported',
    'no hardware key module on $platform',
  );

  @override
  Future<HardwareBacking> create(
    String label, {
    required bool biometric,
  }) async => _throw();

  @override
  Future<bool> exists(String label) async => false;

  @override
  Future<void> delete(String label) async => _throw();

  @override
  Future<HardwareBacking> backing(String label) async => HardwareBacking.none;

  @override
  Future<Uint8List> wrap(String label, Uint8List input) async => _throw();

  @override
  Future<Uint8List> unwrap(
    String label,
    Uint8List blob, {
    required String reason,
  }) async => _throw();

  @override
  Future<HardwareAttestation> attest(String label, Uint8List challenge) async =>
      _throw();
}
