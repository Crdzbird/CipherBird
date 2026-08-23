part of '../cryptolib.dart';

// ── Stateful random-number generators ────────────────────────────────────────
// Two explicitly-seeded generators for when you need reproducibility, an
// auditable reseed trail, or entropy accumulated from your own sources —
// distinct from `randomBytes`, which draws straight from the OS CSPRNG and is
// the right default for ordinary key generation.

/// HMAC-DRBG (NIST SP 800-90A) accumulator.
///
/// Deterministic given the same `(entropy, nonce, personalization)` seed, so it
/// reproduces a stream exactly — useful for test vectors and reproducible
/// derivations. Call [close] when done; the handle holds native memory.
class Drbg {
  Drbg._(this._lib, this._h);

  final CryptoLib _lib;
  Pointer<Void> _h;

  /// Generate [numBytes] (<= 65536) pseudo-random bytes, optionally mixing in
  /// [additional] input for this call only.
  Uint8List generate(int numBytes, [Uint8List? additional]) {
    final add = _toNativeOrNull(additional);
    try {
      return _lib._checkBufResult(
        _lib._lib.lookupFunction<
            CryptoBufferResult Function(Pointer<Void>, Size, Pointer<Uint8>, Size),
            CryptoBufferResult Function(Pointer<Void>, int, Pointer<Uint8>, int)>('cryptolib_drbg_generate')(
          _h, numBytes, add, additional?.length ?? 0),
      );
    } finally {
      if (add != nullptr) calloc.free(add);
    }
  }

  /// Reseed with fresh [entropy] plus optional [additional] input.
  void reseed(Uint8List entropy, [Uint8List? additional]) {
    final e = _lib._toNative(entropy);
    final add = _toNativeOrNull(additional);
    try {
      _lib._checkResult(
        _lib._lib.lookupFunction<
            CryptoResult Function(Pointer<Void>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
            CryptoResult Function(Pointer<Void>, Pointer<Uint8>, int, Pointer<Uint8>, int)>('cryptolib_drbg_reseed')(
          _h, e, entropy.length, add, additional?.length ?? 0),
      );
    } finally {
      if (e != nullptr) calloc.free(e);
      if (add != nullptr) calloc.free(add);
    }
  }

  /// Release the native handle. Idempotent; safe to call more than once.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
        'cryptolib_drbg_free',
      )(_h);
      _h = nullptr;
    }
  }

  Pointer<Uint8> _toNativeOrNull(Uint8List? b) =>
      (b == null || b.isEmpty) ? nullptr : _lib._toNative(b);
}

/// Fortuna-style entropy pool.
///
/// Accumulates entropy events from independent logical sources and reseeds
/// itself once enough has arrived — so it recovers ("heals") after a state
/// compromise, provided at least one source stays unpredictable. Feed it with
/// [addEntropy]; [generate] throws until the pool has seeded at least once.
class Fortuna {
  Fortuna._(this._lib, this._h);

  final CryptoLib _lib;
  Pointer<Void> _h;

  /// Add an entropy event from logical source [sourceId] (0..255). Distinct
  /// sources must use distinct ids — that separation is what the healing
  /// guarantee rests on.
  void addEntropy(int sourceId, Uint8List data) {
    final d = _lib._toNative(data);
    try {
      _lib._lib.lookupFunction<
          Void Function(Pointer<Void>, Uint8, Pointer<Uint8>, Size),
          void Function(Pointer<Void>, int, Pointer<Uint8>, int)>('cryptolib_fortuna_add_entropy')(
        _h, sourceId, d, data.length);
    } finally {
      if (d != nullptr) calloc.free(d);
    }
  }

  /// Generate [numBytes]. Throws if the pool has never reseeded.
  Uint8List generate(int numBytes) => _lib._checkBufResult(
        _lib._lib.lookupFunction<
            CryptoBufferResult Function(Pointer<Void>, Size),
            CryptoBufferResult Function(Pointer<Void>, int)>('cryptolib_fortuna_generate')(_h, numBytes),
      );

  /// Force a reseed now, without waiting for the accumulation threshold.
  void reseed() => _lib._lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
        'cryptolib_fortuna_reseed',
      )(_h);

  /// How many times the pool has reseeded. `0` means never seeded, so
  /// [generate] would throw.
  int reseedCount() => _lib._lib.lookupFunction<
        Uint64 Function(Pointer<Void>), int Function(Pointer<Void>)>('cryptolib_fortuna_reseed_count')(_h);

  /// Release the native handle. Idempotent; safe to call more than once.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<Void Function(Pointer<Void>), void Function(Pointer<Void>)>(
        'cryptolib_fortuna_free',
      )(_h);
      _h = nullptr;
    }
  }
}

/// Stateful RNG constructors on CryptoLib.
extension CryptoLibRng on CryptoLib {
  /// Instantiate an HMAC-DRBG from a caller-supplied seed.
  ///
  /// [entropy] should carry at least 32 bytes of real entropy. [nonce] and
  /// [personalization] provide domain separation so two DRBGs seeded from the
  /// same entropy still produce different streams.
  Drbg drbg(Uint8List entropy, {Uint8List? nonce, Uint8List? personalization}) {
    final e = _toNative(entropy);
    final n = (nonce == null || nonce.isEmpty) ? nullptr : _toNative(nonce);
    final p = (personalization == null || personalization.isEmpty) ? nullptr : _toNative(personalization);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _lib.lookupFunction<
          Pointer<Void> Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Pointer<Utf8>>),
          Pointer<Void> Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Pointer<Utf8>>)>('cryptolib_drbg_instantiate')(
        e, entropy.length, n, nonce?.length ?? 0, p, personalization?.length ?? 0, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      if (h == nullptr) throw Exception('cryptolib: drbg instantiate failed');
      return Drbg._(this, h);
    } finally {
      if (e != nullptr) calloc.free(e);
      if (n != nullptr) calloc.free(n);
      if (p != nullptr) calloc.free(p);
      calloc.free(errPtr);
    }
  }

  /// Create a new, unseeded Fortuna pool. Feed it via [Fortuna.addEntropy]
  /// before generating.
  Fortuna fortuna() {
    final h = _lib.lookupFunction<Pointer<Void> Function(), Pointer<Void> Function()>(
      'cryptolib_fortuna_new',
    )();
    if (h == nullptr) throw Exception('cryptolib: fortuna alloc failed');
    return Fortuna._(this, h);
  }
}
