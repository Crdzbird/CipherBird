part of '../../cipher_bird.dart';

/// MolecularVault - maximum-assurance layered encryption.
///
/// A cascade of XChaCha20-Poly1305 + AES-256-GCM-SIV under a key-committing
/// outer layer, keyed by Argon2id(passphrase) or a 32-byte full-entropy master
/// (e.g. from the hybrid KEM). Composition of vetted primitives only - no new
/// cryptography. Requires the native library built with OpenSSL.
extension CipherBirdMolecularOpenWithKey on CipherBird {
  /// Open a raw-key-sealed envelope.
  Uint8List molecularOpenWithKey(
    Uint8List envelope,
    Uint8List masterKey, {
    Uint8List? aad,
  }) {
    final pe = _toNative(envelope);
    final pk = _toNative(masterKey);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_molecular_open_with_key')(
          pe,
          envelope.length,
          pk,
          masterKey.length,
          pa,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pe != nullptr) {
        calloc.free(pe);
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
