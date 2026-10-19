part of '../../cipher_bird.dart';

/// Keyring operations.
extension CipherBirdKeyringPassphraseSlot on CipherBird {
  /// [keyringAddPassphraseSlot] with the passphrase as bytes to wipe.
  bool keyringAddPassphraseSlotBytes(
    Pointer<Void> kr,
    Uint8List passphrase,
    KdfPreset kdf,
  ) {
    final cpw = _toNativeZ(passphrase);
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
}
