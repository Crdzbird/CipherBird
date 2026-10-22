part of '../../cipher_bird.dart';

/// A FIPS profile key envelope: a 32-byte master secret wrapped by up to 16
/// passphrase (PBKDF2-SHA256) or key-factor (HKDF-SHA256) slots under
/// AES-256-GCM. Adding a slot needs an unlocked envelope. close() when done.
final class FipsEnvelope {
  final CipherBird _cl;
  Pointer<Void> _h;
  FipsEnvelope(this._cl, this._h);

  /// Add a passphrase slot; [iterations] at least 1000.
  void addPassphraseSlot(Uint8List passphrase, {int iterations = 600000}) =>
      _cl._fipsEnvelopeAddPassphrase(_h, passphrase, iterations);

  /// Add a key-factor slot; [factor] at least 32 bytes.
  void addKeySlot(Uint8List factor) => _cl._fipsEnvelopeAddKey(_h, factor);

  /// The master secret, if a passphrase slot opens.
  Uint8List unlockWithPassphrase(Uint8List passphrase) =>
      _cl._fipsEnvelopeUnlockPassphrase(_h, passphrase);

  /// The master secret, if a key slot opens.
  Uint8List unlockWithKey(Uint8List factor) =>
      _cl._fipsEnvelopeUnlockKey(_h, factor);

  /// Drop the slot at [index].
  void removeSlot(int index) => _cl._fipsEnvelopeRemoveSlot(_h, index);

  /// Number of slots.
  int get slotCount => _cl._fipsEnvelopeSlotCount(_h);

  /// The "FKR1" blob to store.
  Uint8List serialise() => _cl._fipsEnvelopeSerialise(_h);

  void close() {
    if (_h != nullptr) {
      _cl._fipsEnvelopeFree(_h);
      _h = nullptr;
    }
  }
}
