part of '../../cipher_bird.dart';

/// Fortuna-style entropy pool.
///
/// Accumulates entropy events from independent logical sources and reseeds
/// itself once enough has arrived - so it recovers ("heals") after a state
/// compromise, provided at least one source stays unpredictable. Feed it with
/// [addEntropy]; [generate] throws until the pool has seeded at least once.
final class Fortuna {
  Fortuna._(this._lib, this._h);

  final CipherBird _lib;
  Pointer<Void> _h;

  /// Add an entropy event from logical source [sourceId] (0..255). Distinct
  /// sources must use distinct ids - that separation is what the healing
  /// guarantee rests on.
  void addEntropy(int sourceId, Uint8List data) {
    final d = _lib._toNative(data);
    try {
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>, Uint8, Pointer<Uint8>, Size),
        void Function(Pointer<Void>, int, Pointer<Uint8>, int)
      >('cryptolib_fortuna_add_entropy')(_h, sourceId, d, data.length);
    } finally {
      if (d != nullptr) {
        calloc.free(d);
      }
    }
  }

  /// Generate [numBytes]. Throws if the pool has never reseeded.
  Uint8List generate(int numBytes) => _lib._checkBufResult(
    _lib._lib.lookupFunction<
      CryptoBufferResult Function(Pointer<Void>, Size),
      CryptoBufferResult Function(Pointer<Void>, int)
    >('cryptolib_fortuna_generate')(_h, numBytes),
  );

  /// Force a reseed now, without waiting for the accumulation threshold.
  void reseed() =>
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >(
        'cryptolib_fortuna_reseed',
      )(_h);

  /// How many times the pool has reseeded. `0` means never seeded, so
  /// [generate] would throw.
  int reseedCount() =>
      _lib._lib.lookupFunction<
        Uint64 Function(Pointer<Void>),
        int Function(Pointer<Void>)
      >('cryptolib_fortuna_reseed_count')(_h);

  /// Release the native handle. Idempotent; safe to call more than once.
  void close() {
    if (_h != nullptr) {
      _lib._lib.lookupFunction<
        Void Function(Pointer<Void>),
        void Function(Pointer<Void>)
      >(
        'cryptolib_fortuna_free',
      )(_h);
      _h = nullptr;
    }
  }
}
