part of '../cryptolib.dart';

/// BBS (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256) methods on CryptoLib.
extension CryptoLibBbs on CryptoLib {
  /// KeyGen from key material (>= 32 B) + optional key info. Throws on failure.
  KeyPairResult bbsKeygen(Uint8List keyMaterial, {Uint8List? keyInfo}) {
    final km = _toNative(keyMaterial);
    final ki = keyInfo != null ? _toNative(keyInfo) : nullptr;
    try {
      final r = _extractKeyPair(
        _lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int, Pointer<Uint8>, int)
        >('cryptolib_bbs_keygen')(
          km,
          keyMaterial.length,
          ki,
          keyInfo?.length ?? 0,
        ),
      );
      if (r.publicKey.isEmpty) {
        throw Exception(
          'cryptolib: bbs keygen failed (key material must be >= 32 bytes)',
        );
      }
      return r;
    } finally {
      if (km != nullptr) calloc.free(km);
      if (ki != nullptr) calloc.free(ki);
    }
  }

  /// Derive the 96-byte public key from a 32-byte secret key.
  Uint8List bbsSkToPk(Uint8List secretKey) {
    final p = _toNative(secretKey);
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)
        >('cryptolib_bbs_sk_to_pk')(p, secretKey.length),
      );
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }
}
