import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/src/hardware/hardware_key.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';
import 'package:cipherbird/src/platform/native/native_platform.dart'
    if (dart.library.js_interop) 'package:cipherbird/src/platform/web/web_platform.dart'
    show Pointer, Void;

/// Keyring slots wrapped by a [HardwareKey].
extension CipherBirdKeyringHardware on CipherBird {
  /// Adds a slot the hardware key wraps; returns the slot index. The
  /// keyring must be unlocked.
  Future<int> keyringAddHardwareSlot(Pointer<Void> kr, HardwareKey key) async {
    final factor = SecretBytes.take(keyringBeginHardwareSlot(kr, key.keyId));
    final index = keyringSlotCount(kr) - 1;
    try {
      final blob = await key.wrap(factor);
      if (!keyringSetHardwareBlob(kr, index, blob)) {
        throw const HardwareKeyException(
          'failed',
          'could not store the wrapped factor',
        );
      }
      return index;
    } finally {
      factor.wipe();
    }
  }

  /// Unlocks the slot wrapped by [key]; returns the master key.
  Future<SecretBytes> keyringUnlockWithHardware(
    Pointer<Void> kr,
    HardwareKey key, {
    String reason = 'Unlock your keys',
  }) async {
    final index = keyringHardwareSlotIndex(kr, key);
    if (index < 0) {
      throw HardwareKeyException('not_found', 'no slot for ${key.label}');
    }
    final (_, blob) = keyringHardwareSlot(kr, index);
    final factor = await key.unwrap(blob, reason: reason);
    try {
      return SecretBytes.take(
        keyringUnlockWithHardwareFactor(kr, index, factor.bytes),
      );
    } finally {
      factor.wipe();
    }
  }

  /// The index of the hardware slot whose key id is [key]'s label, or -1.
  int keyringHardwareSlotIndex(Pointer<Void> kr, HardwareKey key) {
    final wanted = key.keyId;
    for (var i = 0; i < keyringSlotCount(kr); i++) {
      if (keyringSlotType(kr, i) != 2) {
        continue;
      }
      final (id, _) = keyringHardwareSlot(kr, i);
      if (_same(id, wanted)) {
        return i;
      }
    }
    return -1;
  }

  static bool _same(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      return false;
    }
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }
}
