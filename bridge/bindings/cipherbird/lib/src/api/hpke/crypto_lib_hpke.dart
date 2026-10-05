part of '../../cryptolib.dart';

/// HPKE (RFC 9180) methods on CryptoLib.
extension CryptoLibHpke on CryptoLib {
  /// Fresh X25519 key pair for HPKE.
  KeyPairResult hpkeKeygen() => _extractKeyPair(
    _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
      'cryptolib_hpke_keygen',
    )(),
  );

  /// Deterministic DHKEM(X25519).DeriveKeyPair from input keying material.
  KeyPairResult hpkeDeriveKeyPair(Uint8List ikm) {
    final p = _toNative(ikm);
    try {
      return _extractKeyPair(
        _lib.lookupFunction<
          CryptoKeyPair Function(Pointer<Uint8>, Size),
          CryptoKeyPair Function(Pointer<Uint8>, int)
        >('cryptolib_hpke_derive_keypair')(p, ikm.length),
      );
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }
}
