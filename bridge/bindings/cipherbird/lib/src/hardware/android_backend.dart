import 'package:cipherbird/src/hardware/hardware_attestation.dart';
import 'package:cipherbird/src/hardware/hardware_backend.dart';
import 'package:cipherbird/src/hardware/hardware_backing.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';
import 'package:flutter/services.dart';

/// Android Keystore through the plugin's method channel; see
/// `CipherbirdHardwarePlugin.kt`.
final class AndroidBackend implements HardwareBackend {
  const AndroidBackend();

  static const MethodChannel _channel = MethodChannel('cipherbird/hardware');

  Future<T> _call<T>(String method, Map<String, Object?> args) async {
    try {
      final value = await _channel.invokeMethod<T>(method, args);
      if (value == null) {
        throw const HardwareKeyException('failed', 'empty platform reply');
      }
      return value;
    } on PlatformException catch (e) {
      throw HardwareKeyException(e.code, e.message ?? e.code);
    }
  }

  @override
  Future<HardwareBacking> create(
    String label, {
    required bool biometric,
  }) async => HardwareBacking.fromCode(
    await _call<String>('create', {'label': label, 'biometric': biometric}),
  );

  @override
  Future<bool> exists(String label) => _call<bool>('exists', {'label': label});

  @override
  Future<void> delete(String label) => _call<bool>('delete', {'label': label});

  @override
  Future<HardwareBacking> backing(String label) async =>
      HardwareBacking.fromCode(
        await _call<String>('backing', {'label': label}),
      );

  /// Channel replies arrive as unmodifiable lists; secrets must be wipeable.
  Future<Uint8List> _bytes(String method, Map<String, Object?> args) async =>
      Uint8List.fromList(await _call<Uint8List>(method, args));

  @override
  Future<Uint8List> wrap(String label, Uint8List input) =>
      _bytes('wrap', {'label': label, 'input': input});

  @override
  Future<Uint8List> unwrap(
    String label,
    Uint8List blob, {
    required String reason,
  }) => _bytes('unwrap', {'label': label, 'input': blob, 'reason': reason});

  @override
  Future<HardwareAttestation> attest(String label, Uint8List challenge) async {
    final reply = await _call<Map<Object?, Object?>>('attest', {
      'label': label,
      'challenge': challenge,
    });
    return HardwareAttestation(
      kind: AttestationKind.androidKeyAttestation,
      keyId: reply['keyId']! as String,
      document: Uint8List.fromList(reply['document']! as Uint8List),
      publicKey: Uint8List.fromList(reply['publicKey']! as Uint8List),
    );
  }
}
