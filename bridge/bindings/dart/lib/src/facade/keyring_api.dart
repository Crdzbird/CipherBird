part of '../../cryptolib_ffi.dart';

/// Envelope encryption with revocable device and passphrase slots.
extension type KeyringApi(CryptoLib _l) {
  /// New keyring with a fresh random master key.
  Pointer<Void> create() => _l.keyringCreate();

  /// Wrap the master key under a >=32-byte hardware factor key.
  bool addDeviceSlot(Pointer<Void> kr, Uint8List factor) =>
      _l.keyringAddDeviceSlot(kr, factor);

  /// Wrap the master key under an Argon2id passphrase. kdf: 0=interactive, 1=sensitive.
  bool addPassphraseSlot(Pointer<Void> kr, String passphrase, KdfPreset kdf) =>
      _l.keyringAddPassphraseSlot(kr, passphrase, kdf);

  /// Number of slots.
  int slotCount(Pointer<Void> kr) => _l.keyringSlotCount(kr);

  /// Remove (revoke) the slot at [index]. Returns true on success, false if the
  /// index is out of range.
  bool removeSlot(Pointer<Void> kr, int index) =>
      _l.keyringRemoveSlot(kr, index);

  /// Serialise the envelope blob (no plaintext key).
  Uint8List serialise(Pointer<Void> kr) => _l.keyringSerialise(kr);

  /// Parse an envelope blob into a (locked) keyring handle (nullptr on error).
  Pointer<Void> deserialise(Uint8List blob) => _l.keyringDeserialise(blob);

  /// Recover the master key with a device factor key.
  Uint8List unlockWithDevice(Pointer<Void> kr, Uint8List factor) =>
      _l.keyringUnlockWithDevice(kr, factor);

  /// Recover the master key with a passphrase.
  Uint8List unlockWithPassphrase(Pointer<Void> kr, String passphrase) =>
      _l.keyringUnlockWithPassphrase(kr, passphrase);

  /// Free a keyring handle.
  void free(Pointer<Void> kr) => _l.keyringFree(kr);
}
