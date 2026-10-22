part of '../../cipher_bird.dart';

extension CipherBirdFipsEnvelopeSlots on CipherBird {
  void _fipsEnvelopeRemoveSlot(Pointer<Void> h, int index) {
    _checkResult(
      _lib.lookupFunction<
        CipherBirdResult Function(Pointer<Void>, Size),
        CipherBirdResult Function(Pointer<Void>, int)
      >('cryptolib_fips_envelope_remove_slot')(h, index),
    );
  }

  int _fipsEnvelopeSlotCount(Pointer<Void> h) {
    return _lib.lookupFunction<
      Size Function(Pointer<Void>),
      int Function(Pointer<Void>)
    >('cryptolib_fips_envelope_slot_count')(h);
  }

  Uint8List _fipsEnvelopeSerialise(Pointer<Void> h) {
    return _checkBufResult(
      _lib.lookupFunction<
        CipherBirdBufferResult Function(Pointer<Void>),
        CipherBirdBufferResult Function(Pointer<Void>)
      >('cryptolib_fips_envelope_serialise')(h),
    );
  }
}
