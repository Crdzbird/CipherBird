part of '../cryptolib.dart';

/// Keyring operations.
extension CryptoLibKeyring on CryptoLib {
  /// New keyring with a fresh random master key.
  Pointer<Void> keyringCreate() =>
      _lib.lookupFunction<Pointer<Void> Function(), Pointer<Void> Function()>(
        'cryptolib_keyring_create',
      )();

  /// Wrap the master key under a >=32-byte hardware factor key.
  bool keyringAddDeviceSlot(Pointer<Void> kr, Uint8List factor) {
    final p = malloc<Uint8>(factor.length);
    p.asTypedList(factor.length).setAll(0, factor);
    try {
      return _lib.lookupFunction<
            Int32 Function(Pointer<Void>, Pointer<Uint8>, Size),
            int Function(Pointer<Void>, Pointer<Uint8>, int)
          >('cryptolib_keyring_add_device_slot')(kr, p, factor.length) ==
          1;
    } finally {
      malloc.free(p);
    }
  }

  /// Wrap the master key under an Argon2id passphrase.
  bool keyringAddPassphraseSlot(
    Pointer<Void> kr,
    String passphrase,
    KdfPreset kdf,
  ) {
    final cpw = passphrase.toNativeUtf8();
    try {
      return _lib.lookupFunction<
            Int32 Function(Pointer<Void>, Pointer<Utf8>, Int32),
            int Function(Pointer<Void>, Pointer<Utf8>, int)
          >('cryptolib_keyring_add_passphrase_slot')(kr, cpw, kdf.value) ==
          1;
    } finally {
      malloc.free(cpw);
    }
  }

  /// Number of slots.
  int keyringSlotCount(Pointer<Void> kr) =>
      _lib.lookupFunction<
        Size Function(Pointer<Void>),
        int Function(Pointer<Void>)
      >('cryptolib_keyring_slot_count')(kr);

  /// Serialise the envelope blob (no plaintext key).
  Uint8List keyringSerialise(Pointer<Void> kr) => _checkBufResult(
    _lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>),
      CryptoBufferResult Function(Pointer<Void>)
    >('cryptolib_keyring_serialise')(kr),
  );

  /// Parse an envelope blob into a (locked) keyring handle (nullptr on error).
  Pointer<Void> keyringDeserialise(Uint8List blob) {
    final p = malloc<Uint8>(blob.length);
    p.asTypedList(blob.length).setAll(0, blob);
    final errPtr = malloc<Pointer<Utf8>>()..value = nullptr;
    try {
      return _lib.lookupFunction<
        Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
        Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)
      >('cryptolib_keyring_deserialise')(p, blob.length, errPtr);
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
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Void>, Pointer<Uint8>, int)
        >('cryptolib_keyring_unlock_with_device')(kr, p, factor.length),
      );
    } finally {
      malloc.free(p);
    }
  }
}
