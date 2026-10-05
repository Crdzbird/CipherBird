part of '../../cipher_bird.dart';

/// MolecularVault - maximum-assurance layered encryption.
///
/// A cascade of XChaCha20-Poly1305 + AES-256-GCM-SIV under a key-committing
/// outer layer, keyed by Argon2id(passphrase) or a 32-byte full-entropy master
/// (e.g. from the hybrid KEM). Composition of vetted primitives only - no new
/// cryptography. Requires the native library built with OpenSSL.
extension CipherBirdMolecularOpen on CipherBird {
  /// Open a passphrase-sealed envelope. A wrong passphrase, wrong [aad], or any
  /// tampering throws (fails closed) rather than returning garbage.
  Uint8List molecularOpen(
    Uint8List envelope,
    String passphrase, {
    Uint8List? aad,
  }) {
    final pe = _toNative(envelope);
    final cpw = passphrase.toNativeUtf8();
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
          ),
          CipherBirdBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
          )
        >('cryptolib_molecular_open')(
          pe,
          envelope.length,
          cpw,
          pa,
          aad?.length ?? 0,
        ),
      );
    } finally {
      if (pe != nullptr) {
        calloc.free(pe);
      }
      calloc.free(cpw);
      if (pa != nullptr) {
        calloc.free(pa);
      }
    }
  }
}
