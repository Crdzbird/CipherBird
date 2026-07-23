part of '../cryptolib.dart';

// ── OPRF — Oblivious Pseudorandom Function (RFC 9497, ristretto255-SHA-512) ────
// Client blinds its input; server evaluates under its key without seeing it;
// client unblinds to the PRF output. Privacy Pass, PSI, password hardening, OPAQUE.

/// Client OPRF Blind output: the secret blind + the blinded element to send.
class OprfBlindResult {
  final Uint8List blind;
  final Uint8List blindedElement;
  OprfBlindResult(this.blind, this.blindedElement);
}

/// OPRF (RFC 9497) methods on CryptoLib.
extension CryptoLibOprf on CryptoLib {
  /// Derive an OPRF key pair from a seed (+ optional info). Throws on failure.
  KeyPairResult oprfDeriveKeyPair(Uint8List seed, {Uint8List? info}) {
    final s = _toNative(seed);
    final i = info != null ? _toNative(info) : nullptr;
    try {
      final r = _extractKeyPair(_lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_oprf_derive_keypair')(
          s, seed.length, i, info?.length ?? 0));
      if (r.publicKey.isEmpty) throw Exception('cryptolib: oprf derive_keypair failed');
      return r;
    } finally { if (s != nullptr) calloc.free(s); if (i != nullptr) calloc.free(i); }
  }

  /// Client: blind an input with a fresh random scalar.
  OprfBlindResult oprfBlind(Uint8List input) {
    final p = _toNative(input);
    try {
      final c = _lib.lookupFunction<
          CryptoOprfBlind Function(Pointer<Uint8>, Size),
          CryptoOprfBlind Function(Pointer<Uint8>, int)>('cryptolib_oprf_blind')(p, input.length);
      return _oprfBlindOut(c);
    } finally { if (p != nullptr) calloc.free(p); }
  }

  /// Deterministic blind with a caller-supplied scalar (test vectors).
  OprfBlindResult oprfBlindWithScalar(Uint8List input, Uint8List blind) {
    final p = _toNative(input), b = _toNative(blind);
    try {
      final c = _lib.lookupFunction<
          CryptoOprfBlind Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoOprfBlind Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_oprf_blind_with_scalar')(
          p, input.length, b, blind.length);
      return _oprfBlindOut(c);
    } finally { if (p != nullptr) calloc.free(p); if (b != nullptr) calloc.free(b); }
  }

  OprfBlindResult _oprfBlindOut(CryptoOprfBlind c) {
    if (c.error != nullptr) {
      final m = c.error.toDartString();
      _oprfBlindFree(c);
      throw Exception(m);
    }
    final r = OprfBlindResult(_frostCopy(c.blind), _frostCopy(c.blindedElement));
    _oprfBlindFree(c);
    return r;
  }

  void _oprfBlindFree(CryptoOprfBlind c) {
    final p = calloc<CryptoOprfBlind>();
    p.ref.blind.data = c.blind.data; p.ref.blind.len = c.blind.len;
    p.ref.blindedElement.data = c.blindedElement.data; p.ref.blindedElement.len = c.blindedElement.len;
    p.ref.error = c.error;
    _lib.lookupFunction<Void Function(Pointer<CryptoOprfBlind>),
        void Function(Pointer<CryptoOprfBlind>)>('cryptolib_oprf_blind_free')(p);
    calloc.free(p);
  }

  /// Server: evaluate a blinded element under the secret key.
  Uint8List oprfBlindEvaluate(Uint8List secretKey, Uint8List blindedElement) {
    final s = _toNative(secretKey), b = _toNative(blindedElement);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_oprf_blind_evaluate')(
          s, secretKey.length, b, blindedElement.length));
    } finally { if (s != nullptr) calloc.free(s); if (b != nullptr) calloc.free(b); }
  }

  /// Client: unblind the evaluated element → 64-byte PRF output.
  Uint8List oprfFinalize(Uint8List input, Uint8List blind, Uint8List evaluatedElement) {
    final p = _toNative(input), b = _toNative(blind), e = _toNative(evaluatedElement);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_oprf_finalize')(
          p, input.length, b, blind.length, e, evaluatedElement.length));
    } finally {
      if (p != nullptr) calloc.free(p); if (b != nullptr) calloc.free(b); if (e != nullptr) calloc.free(e);
    }
  }

  /// Server one-shot: compute the PRF output directly from the key + input.
  Uint8List oprfEvaluate(Uint8List secretKey, Uint8List input) {
    final s = _toNative(secretKey), p = _toNative(input);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_oprf_evaluate')(
          s, secretKey.length, p, input.length));
    } finally { if (s != nullptr) calloc.free(s); if (p != nullptr) calloc.free(p); }
  }
}
