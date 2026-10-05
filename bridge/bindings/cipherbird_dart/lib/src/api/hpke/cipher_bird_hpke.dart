part of '../../cipher_bird.dart';

/// HPKE (RFC 9180) methods on CipherBird.
extension CipherBirdHpke on CipherBird {
  /// Fresh X25519 key pair for HPKE.
  KeyPairResult hpkeKeygen() => _extractKeyPair(
    _lib.lookupFunction<
      CipherBirdKeyPair Function(),
      CipherBirdKeyPair Function()
    >(
      'cryptolib_hpke_keygen',
    )(),
  );

  /// Deterministic DHKEM(X25519).DeriveKeyPair from input keying material.
  KeyPairResult hpkeDeriveKeyPair(Uint8List ikm) {
    final p = _toNative(ikm);
    try {
      return _extractKeyPair(
        _lib.lookupFunction<
          CipherBirdKeyPair Function(Pointer<Uint8>, Size),
          CipherBirdKeyPair Function(Pointer<Uint8>, int)
        >('cryptolib_hpke_derive_keypair')(p, ikm.length),
      );
    } finally {
      if (p != nullptr) calloc.free(p);
    }
  }
}
