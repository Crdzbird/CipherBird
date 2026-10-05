part of '../../cryptolib.dart';

/// OPRF (RFC 9497) methods on CryptoLib.
extension CryptoLibOprf on CryptoLib {
  /// Derive an OPRF key pair from a seed (+ optional info). Throws on failure.
  KeyPairResult oprfDeriveKeyPair(Uint8List seed, {Uint8List? info}) {
    final s = _toNative(seed);
    final i = info != null ? _toNative(info) : nullptr;
    try {
      final r = _extractKeyPair(
        _lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_oprf_derive_keypair')(
          s,
          seed.length,
          i,
          info?.length ?? 0,
        ),
      );
      if (r.publicKey.isEmpty) {
        throw Exception('cryptolib: oprf derive_keypair failed');
      }
      return r;
    } finally {
      if (s != nullptr) calloc.free(s);
      if (i != nullptr) calloc.free(i);
    }
  }

  /// Client: blind an input with a fresh random scalar.
  OprfBlindResult oprfBlind(Uint8List input) {
    final p = _toNative(input);
    try {
      final c = _lib
          .lookupFunction<
            CryptoOprfBlind Function(Pointer<Uint8>, Size),
            CryptoOprfBlind Function(Pointer<Uint8>, int)
          >('cryptolib_oprf_blind')(p, input.length);
      return _oprfBlindOut(c);
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  /// Deterministic blind with a caller-supplied scalar (test vectors).
  OprfBlindResult oprfBlindWithScalar(Uint8List input, Uint8List blind) {
    final p = _toNative(input), b = _toNative(blind);
    try {
      final c = _lib
          .lookupFunction<
            CryptoOprfBlind Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            CryptoOprfBlind Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
          >(
            'cryptolib_oprf_blind_with_scalar',
          )(p, input.length, b, blind.length);
      return _oprfBlindOut(c);
    } finally {
      if (p != nullptr) calloc.free(p);
      if (b != nullptr) calloc.free(b);
    }
  }

  OprfBlindResult _oprfBlindOut(CryptoOprfBlind c) {
    if (c.error != nullptr) {
      final m = c.error.toDartString();
      _oprfBlindFree(c);
      throw Exception(m);
    }
    final r = OprfBlindResult(
      _frostCopy(c.blind),
      _frostCopy(c.blindedElement),
    );
    _oprfBlindFree(c);
    return r;
  }

  void _oprfBlindFree(CryptoOprfBlind c) {
    final p = calloc<CryptoOprfBlind>();
    p.ref.blind.data = c.blind.data;
    p.ref.blind.len = c.blind.len;
    p.ref.blindedElement.data = c.blindedElement.data;
    p.ref.blindedElement.len = c.blindedElement.len;
    p.ref.error = c.error;
    _lib.lookupFunction<
      Void Function(Pointer<CryptoOprfBlind>),
      void Function(Pointer<CryptoOprfBlind>)
    >('cryptolib_oprf_blind_free')(p);
    calloc.free(p);
  }
}
