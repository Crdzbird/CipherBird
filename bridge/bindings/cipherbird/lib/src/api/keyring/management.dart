part of '../../cipher_bird.dart';

/// Keyring operations.
extension CipherBirdKeyringManagement on CipherBird {
  /// Recover the master key with a passphrase.
  Uint8List keyringUnlockWithPassphrase(Pointer<Void> kr, String passphrase) {
    final bytes = utf8.encode(passphrase);
    try {
      return keyringUnlockWithPassphraseBytes(kr, bytes);
    } finally {
      bytes.wipe();
    }
  }

  /// [keyringUnlockWithPassphrase] with the passphrase as bytes to wipe.
  Uint8List keyringUnlockWithPassphraseBytes(
    Pointer<Void> kr,
    Uint8List passphrase,
  ) {
    final cpw = _toNativeZ(passphrase);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Utf8>),
          CipherBirdBufferResult Function(Pointer<Void>, Pointer<Utf8>)
        >('cryptolib_keyring_unlock_with_passphrase')(kr, cpw),
      );
    } finally {
      malloc.free(cpw);
    }
  }

  /// Free a keyring handle.
  void keyringFree(Pointer<Void> kr) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_keyring_free')(kr);

  /// Remove (revoke) the slot at [index]. Returns true on success, false if the
  /// index is out of range.
  bool keyringRemoveSlot(Pointer<Void> kr, int index) =>
      _lib.lookupFunction<
        Int32 Function(Pointer<Void>, Size),
        int Function(Pointer<Void>, int)
      >('cryptolib_keyring_remove_slot')(kr, index) ==
      1;
}
