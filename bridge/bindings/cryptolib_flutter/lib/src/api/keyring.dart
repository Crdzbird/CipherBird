part of '../cryptolib.dart';

/// Keyring operations.
extension CryptoLibKeyring on CryptoLib {
  // ── Keyring (envelope / key-slots) ────────────────────────────────────────

  /// New keyring with a fresh random master key.
  Pointer<Void> keyringCreate() =>
      _lib.lookupFunction<Pointer<Void> Function(), Pointer<Void> Function()>(
          'cryptolib_keyring_create')();

  /// Wrap the master key under a >=32-byte hardware factor key.
  bool keyringAddDeviceSlot(Pointer<Void> kr, Uint8List factor) {
    final p = malloc<Uint8>(factor.length);
    p.asTypedList(factor.length).setAll(0, factor);
    try {
      return _lib.lookupFunction<Int32 Function(Pointer<Void>, Pointer<Uint8>, Size),
              int Function(Pointer<Void>, Pointer<Uint8>, int)>(
          'cryptolib_keyring_add_device_slot')(kr, p, factor.length) == 1;
    } finally {
      malloc.free(p);
    }
  }

  /// Wrap the master key under an Argon2id passphrase. kdf: 0=interactive, 1=sensitive.
  bool keyringAddPassphraseSlot(Pointer<Void> kr, String passphrase, int kdf) {
    final cpw = passphrase.toNativeUtf8();
    try {
      return _lib.lookupFunction<Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32),
              int Function(Pointer<Void>, Pointer<Utf8>, int)>(
          'cryptolib_keyring_add_passphrase_slot')(kr, cpw, kdf) == 1;
    } finally {
      malloc.free(cpw);
    }
  }

  /// Number of slots.
  int keyringSlotCount(Pointer<Void> kr) =>
      _lib.lookupFunction<Size Function(Pointer<Void>), int Function(Pointer<Void>)>(
          'cryptolib_keyring_slot_count')(kr);

  /// Serialise the envelope blob (no plaintext key).
  Uint8List keyringSerialise(Pointer<Void> kr) => _checkBufResult(
      _lib.lookupFunction<CryptoBufferResult Function(Pointer<Void>),
              CryptoBufferResult Function(Pointer<Void>)>(
          'cryptolib_keyring_serialise')(kr));

  /// Parse an envelope blob into a (locked) keyring handle (nullptr on error).
  Pointer<Void> keyringDeserialise(Uint8List blob) {
    final p = malloc<Uint8>(blob.length);
    p.asTypedList(blob.length).setAll(0, blob);
    final errPtr = malloc<Pointer<Utf8>>()..value = nullptr;
    try {
      return _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>(
          'cryptolib_keyring_deserialise')(p, blob.length, errPtr);
    } finally {
      malloc.free(p);
      malloc.free(errPtr);
    }
  }

  /// Recover the master key with a device factor key.
  Uint8List keyringUnlockWithDevice(Pointer<Void> kr, Uint8List factor) {
    final p = malloc<Uint8>(factor.length);
    p.asTypedList(factor.length).setAll(0, factor);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)>(
          'cryptolib_keyring_unlock_with_device')(kr, p, factor.length));
    } finally {
      malloc.free(p);
    }
  }

  /// Recover the master key with a passphrase.
  Uint8List keyringUnlockWithPassphrase(Pointer<Void> kr, String passphrase) {
    final cpw = passphrase.toNativeUtf8();
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Utf8>),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Utf8>)>(
          'cryptolib_keyring_unlock_with_passphrase')(kr, cpw));
    } finally {
      malloc.free(cpw);
    }
  }

  /// Free a keyring handle.
  void keyringFree(Pointer<Void> kr) =>
      _lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
          'cryptolib_keyring_free')(kr);


  /// Remove (revoke) the slot at [index]. Returns true on success, false if the
  /// index is out of range.
  bool keyringRemoveSlot(Pointer<Void> kr, int index) =>
      _lib.lookupFunction<Int32 Function(Pointer<Void>, Size),
              int Function(Pointer<Void>, int)>(
          'cryptolib_keyring_remove_slot')(kr, index) == 1;
}
