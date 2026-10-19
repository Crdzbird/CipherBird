part of '../../cipher_bird.dart';

/// Keyring hardware slots: reading a slot and unlocking with its factor.
extension CipherBirdKeyringHardwareSlotsRead on CipherBird {
  /// Key id and module-wrapped factor of the hardware slot at [index].
  (Uint8List keyId, Uint8List blob) keyringHardwareSlot(
    Pointer<Void> kr,
    int index,
  ) {
    final outId = calloc<CipherBirdBuffer>();
    final outBlob = calloc<CipherBirdBuffer>();
    try {
      final ok =
          _lib.lookupFunction<
            Int32 Function(
              Pointer<Void>,
              Size,
              Pointer<CipherBirdBuffer>,
              Pointer<CipherBirdBuffer>,
            ),
            int Function(
              Pointer<Void>,
              int,
              Pointer<CipherBirdBuffer>,
              Pointer<CipherBirdBuffer>,
            )
          >('cryptolib_keyring_hardware_slot')(kr, index, outId, outBlob) ==
          1;
      if (!ok) {
        throw StateError('cipherbird: slot $index is not a hardware slot');
      }
      return (_copyBuf(outId.ref), _copyBuf(outBlob.ref));
    } finally {
      calloc.free(outId);
      calloc.free(outBlob);
    }
  }

  /// Recover the master key with the factor the module unwrapped for the
  /// hardware slot at [index].
  Uint8List keyringUnlockWithHardwareFactor(
    Pointer<Void> kr,
    int index,
    Uint8List factor,
  ) {
    final pf = _toNative(factor);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Void>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Void>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_keyring_unlock_with_hardware')(
          kr,
          index,
          pf,
          factor.length,
        ),
      );
    } finally {
      if (pf != nullptr) {
        calloc.free(pf);
      }
    }
  }
}
