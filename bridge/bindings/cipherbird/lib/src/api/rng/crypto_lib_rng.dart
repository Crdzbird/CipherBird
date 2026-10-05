part of '../../cryptolib.dart';

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
    final p = (personalization == null || personalization.isEmpty)
        ? nullptr
        : _toNative(personalization);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h =
          _lib.lookupFunction<
            Pointer<Void> Function(
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Pointer<Utf8>>,
            ),
            Pointer<Void> Function(
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Pointer<Utf8>>,
            )
          >('cryptolib_drbg_instantiate')(
            e,
            entropy.length,
            n,
            nonce?.length ?? 0,
            p,
            personalization?.length ?? 0,
            errPtr,
          );
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(msg);
      }
      if (h == nullptr) {
        throw Exception('cryptolib: drbg instantiate failed');
      }
      return Drbg._(this, h);
    } finally {
      if (e != nullptr) {
        calloc.free(e);
      }
      if (n != nullptr) {
        calloc.free(n);
      }
      if (p != nullptr) {
        calloc.free(p);
      }
      calloc.free(errPtr);
    }
  }

  /// Create a new, unseeded Fortuna pool. Feed it via [Fortuna.addEntropy]
  /// before generating.
  Fortuna fortuna() {
    final h = _lib
        .lookupFunction<Pointer<Void> Function(), Pointer<Void> Function()>(
          'cryptolib_fortuna_new',
        )();
    if (h == nullptr) {
      throw Exception('cryptolib: fortuna alloc failed');
    }
    return Fortuna._(this, h);
  }
}
