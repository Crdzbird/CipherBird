/// Hardware-backed keys for CipherBird: a key that lives in the Secure
/// Enclave (iOS, macOS) or the Android Keystore (StrongBox where the device
/// has one, otherwise the trusted execution environment) wraps a keyring
/// slot, optionally behind the system biometric prompt, and can be attested
/// for a server. Flutter only; the browser and the pure Dart package have
/// no key module.
///
/// ```dart
/// final key = await HardwareKey.create('bank-possession', biometric: true);
/// final kr = CipherBird.instance.keyringCreate();
/// await CipherBird.instance.keyringAddHardwareSlot(kr, key);
/// final master = await CipherBird.instance.keyringUnlockWithHardware(kr, key);
/// ```
library;

export 'src/hardware/hardware_attestation.dart';
export 'src/hardware/hardware_backend.dart';
export 'src/hardware/hardware_backing.dart';
export 'src/hardware/hardware_key.dart';
export 'src/hardware/hardware_key_exception.dart';
export 'src/hardware/keyring_hardware.dart';
export 'src/hardware/unsupported_backend.dart';
