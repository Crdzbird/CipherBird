part of '../../cipher_bird.dart';

/// FIPS profile envelope construction on CipherBird.
extension CipherBirdFipsEnvelope on CipherBird {
  /// A fresh envelope with a module-generated master secret and no slots.
  FipsEnvelope fipsEnvelopeCreate() {
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib
          .lookupFunction<
            Pointer<Void> Function(Pointer<Pointer<Utf8>>),
            Pointer<Void> Function(Pointer<Pointer<Utf8>>)
          >('cryptolib_fips_envelope_create')(errPtr);
      return _fipsEnvelopeHandle(h, errPtr);
    } finally {
      calloc.free(errPtr);
    }
  }

  /// A stored envelope; unlock it before adding slots.
  FipsEnvelope fipsEnvelopeDeserialise(Uint8List blob) {
    final pb = _toNative(blob);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib
          .lookupFunction<
            Pointer<Void> Function(
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)
          >('cryptolib_fips_envelope_deserialise')(pb, blob.length, errPtr);
      return _fipsEnvelopeHandle(h, errPtr);
    } finally {
      if (pb != nullptr) calloc.free(pb);
      calloc.free(errPtr);
    }
  }

  FipsEnvelope _fipsEnvelopeHandle(
    Pointer<Void> h,
    Pointer<Pointer<Utf8>> errPtr,
  ) {
    if (errPtr.value != nullptr) {
      final m = errPtr.value.toDartString();
      _core.strFree(errPtr.value);
      throw Exception(m);
    }
    if (h == nullptr) {
      throw Exception('cipherbird: fips envelope failed');
    }
    return FipsEnvelope(this, h);
  }

  void _fipsEnvelopeFree(Pointer<Void> h) =>
      _lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >('cryptolib_fips_envelope_free')(h);
}
