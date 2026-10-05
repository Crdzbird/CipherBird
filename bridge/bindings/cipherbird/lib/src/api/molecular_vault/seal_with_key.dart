part of '../../cipher_bird.dart';

/// MolecularVault - maximum-assurance layered encryption.
///
/// A cascade of XChaCha20-Poly1305 + AES-256-GCM-SIV under a key-committing
/// outer layer, keyed by Argon2id(passphrase) or a 32-byte full-entropy master
/// (e.g. from the hybrid KEM). Composition of vetted primitives only - no new
/// cryptography. Requires the native library built with OpenSSL.
extension CipherBirdMolecularSealWithKey on CipherBird {
  /// Seal under a 32-byte full-entropy [masterKey] (e.g. a hybrid-KEM shared
  /// secret). No Argon2id is applied - the key is assumed to be full-entropy.
  Uint8List molecularSealWithKey(
    Uint8List plaintext,
    Uint8List masterKey, {
    Uint8List? aad,
  }) {
    final pp = _toNative(plaintext);
    final pk = _toNative(masterKey);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_molecular_seal_with_key')(
          pp,
          plaintext.length,
          pk,
          masterKey.length,
          pa,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
      if (pa != nullptr) {
        calloc.free(pa);
      }
    }
  }
}
