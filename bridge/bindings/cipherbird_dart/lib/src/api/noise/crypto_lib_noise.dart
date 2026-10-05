part of '../../cryptolib.dart';

/// Incremental BLAKE3 and Noise XX constructors on CryptoLib.
extension CryptoLibNoise on CryptoLib {
  /// Incremental BLAKE3; pass a 32-byte [key] for keyed (MAC) mode.
  Blake3Hasher blake3Hasher({Uint8List? key}) {
    if (key != null && key.length != 32) {
      throw ArgumentError('cryptolib: BLAKE3 key must be exactly 32 bytes');
    }
    final p = (key == null) ? nullptr : _toNative(key);
    try {
      final h = _lib
          .lookupFunction<
            Pointer<Void> Function(Pointer<Uint8>, Size),
            Pointer<Void> Function(Pointer<Uint8>, int)
          >('cryptolib_blake3_hasher_create')(p, key?.length ?? 0);
      if (h == nullptr) {
        throw Exception(
          'cryptolib: blake3 hasher create failed (BLAKE3 not enabled?)',
        );
      }
      return Blake3Hasher._(this, h);
    } finally {
      if (p != nullptr) {
        calloc.free(p);
      }
    }
  }

  /// Create a Noise XX state from this side's X25519 keypair (see
  /// `x25519Keygen`). Both sides must use the same [prologue].
  NoiseXX noise({
    required bool initiator,
    required Uint8List staticPublic,
    required Uint8List staticSecret,
    Uint8List? prologue,
  }) {
    if (staticPublic.length != 32 || staticSecret.length != 32) {
      throw ArgumentError('cryptolib: Noise static keys must be 32 bytes each');
    }
    final pp = _toNative(staticPublic), ps = _toNative(staticSecret);
    final pr = (prologue == null || prologue.isEmpty)
        ? nullptr
        : _toNative(prologue);
    try {
      final h = _lib
          .lookupFunction<
            Pointer<Void> Function(
              Int32,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
              Pointer<Uint8>,
              Size,
            ),
            Pointer<Void> Function(
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
              Pointer<Uint8>,
              int,
            )
          >(
            'cryptolib_noise_create',
          )(initiator ? 1 : 0, pp, 32, ps, 32, pr, prologue?.length ?? 0);
      if (h == nullptr) {
        throw Exception('cryptolib: noise create failed');
      }
      return NoiseXX._(this, h);
    } finally {
      calloc.free(pp);
      calloc.free(ps);
      if (pr != nullptr) {
        calloc.free(pr);
      }
    }
  }
}
