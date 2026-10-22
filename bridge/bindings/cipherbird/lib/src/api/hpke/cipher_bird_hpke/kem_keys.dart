part of '../../../cipher_bird.dart';

/// HPKE key pairs for a chosen KEM on CipherBird.
extension CipherBirdHpkeKemKeys on CipherBird {
  /// Whether this build offers [kem].
  bool hpkeKemAvailable(HpkeKem kem) {
    return _lib.lookupFunction<Int32 Function(Int32), int Function(int)>(
          'cryptolib_hpke_kem_available',
        )(kem.value) ==
        1;
  }

  /// Random key pair for [kem].
  KeyPairResult hpkeKeygenKem(HpkeKem kem) {
    return _extractKeyPair(
      _lib.lookupFunction<
        CipherBirdKeyPair Function(Int32),
        CipherBirdKeyPair Function(int)
      >('cryptolib_hpke_keygen_kem')(kem.value),
    );
  }

  /// Deterministic DeriveKeyPair for [kem] from input keying material.
  KeyPairResult hpkeDeriveKeypairKem(HpkeKem kem, Uint8List ikm) {
    final ikmPtr = _toNative(ikm);
    try {
      return _extractKeyPair(
        _lib.lookupFunction<
          CipherBirdKeyPair Function(Int32, Pointer<Uint8>, Size),
          CipherBirdKeyPair Function(int, Pointer<Uint8>, int)
        >('cryptolib_hpke_derive_keypair_kem')(kem.value, ikmPtr, ikm.length),
      );
    } finally {
      if (ikmPtr != nullptr) calloc.free(ikmPtr);
    }
  }
}
