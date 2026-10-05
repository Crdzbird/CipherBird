part of '../../cipher_bird.dart';

/// OPRF (RFC 9497) methods on CipherBird.
extension CipherBirdOprf on CipherBird {
  /// Derive an OPRF key pair from a seed (+ optional info). Throws on failure.
  KeyPairResult oprfDeriveKeyPair(Uint8List seed, {Uint8List? info}) {
    final s = _toNative(seed);
    final i = info != null ? _toNative(info) : nullptr;
    try {
      final r = _extractKeyPair(
        _lib.lookupFunction<
          CipherBirdKeyPair Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdKeyPair Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_oprf_derive_keypair')(
          s,
          seed.length,
          i,
          info?.length ?? 0,
        ),
      );
      if (r.publicKey.isEmpty) {
        throw Exception('cipherbird: oprf derive_keypair failed');
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
            CipherBirdOprfBlind Function(Pointer<Uint8>, Size),
            CipherBirdOprfBlind Function(Pointer<Uint8>, int)
          >('cryptolib_oprf_blind')(p, input.length);
      return _oprfBlindOut(c);
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }

  OprfBlindResult _oprfBlindOut(CipherBirdOprfBlind c) {
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

  void _oprfBlindFree(CipherBirdOprfBlind c) {
    final p = calloc<CipherBirdOprfBlind>();
    p.ref.blind.data = c.blind.data;
    p.ref.blind.len = c.blind.len;
    p.ref.blindedElement.data = c.blindedElement.data;
    p.ref.blindedElement.len = c.blindedElement.len;
    p.ref.error = c.error;
    _lib.lookupFunction<
      Void Function(Pointer<CipherBirdOprfBlind>),
      void Function(Pointer<CipherBirdOprfBlind>)
    >('cryptolib_oprf_blind_free')(p);
    calloc.free(p);
  }
}
