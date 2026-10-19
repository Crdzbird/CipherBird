part of '../../cipher_bird.dart';

/// Keyring hardware slots: the raw C ABI. The `HardwareKey` library in
/// `package:cipherbird/cipherbird_hardware.dart` drives these with the
/// platform key module; use them directly only with your own module.
extension CipherBirdKeyringHardwareSlots on CipherBird {
  /// Add a hardware slot named by [keyId]; returns the fresh 32-byte factor
  /// the module must wrap. Wipe it once wrapped.
  Uint8List keyringBeginHardwareSlot(Pointer<Void> kr, Uint8List keyId) {
    final pid = _toNative(keyId);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_keyring_add_hardware_slot')(kr, pid, keyId.length),
      );
    } finally {
      if (pid != nullptr) {
        calloc.free(pid);
      }
    }
  }

  /// Store the module-wrapped factor for the hardware slot at [index].
  bool keyringSetHardwareBlob(Pointer<Void> kr, int index, Uint8List blob) {
    final pb = _toNative(blob);
    try {
      return _lib.lookupFunction<
            Int32 Function(Pointer<Void>, Size, Pointer<Uint8>, Size),
            int Function(Pointer<Void>, int, Pointer<Uint8>, int)
          >('cryptolib_keyring_set_hardware_blob')(
            kr,
            index,
            pb,
            blob.length,
          ) ==
          1;
    } finally {
      if (pb != nullptr) {
        calloc.free(pb);
      }
    }
  }

  /// Slot type at [index]: 0 passphrase, 1 device, 2 hardware, -1 bad index.
  int keyringSlotType(Pointer<Void> kr, int index) =>
      _lib.lookupFunction<
        Int32 Function(Pointer<Void>, Size),
        int Function(Pointer<Void>, int)
      >('cryptolib_keyring_slot_type')(kr, index);
}
