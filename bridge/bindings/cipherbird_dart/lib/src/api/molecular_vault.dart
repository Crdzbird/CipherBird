part of '../cipher_bird.dart';

/// MolecularVault - maximum-assurance layered encryption.
///
/// A cascade of XChaCha20-Poly1305 + AES-256-GCM-SIV under a key-committing
/// outer layer, keyed by Argon2id(passphrase) or a 32-byte full-entropy master
/// (e.g. from the hybrid KEM). Composition of vetted primitives only - no new
/// cryptography. Requires the native library built with OpenSSL.
extension CipherBirdMolecular on CipherBird {
  /// Seal [plaintext] under a [passphrase]. [ops]/[mem] are the Argon2id work
  /// factors; pass 0 for either to use the library's SENSITIVE preset. Raise
  /// [mem] toward 1 << 30 (1 GiB) to make password guessing far costlier. The
  /// returned envelope is self-describing (carries the salt and parameters).
  Uint8List molecularSeal(
    Uint8List plaintext,
    String passphrase, {
    Uint8List? aad,
    int ops = 0,
    int mem = 0,
  }) {
    final pp = _toNative(plaintext);
    final cpw = passphrase.toNativeUtf8();
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(
        _lib.lookupFunction<
          CryptoBufferResult Function(
            Pointer<Uint8>,
            Size,
            Pointer<Utf8>,
            Pointer<Uint8>,
            Size,
            Uint64,
            Size,
          ),
          CryptoBufferResult Function(
            Pointer<Uint8>,
            int,
            Pointer<Utf8>,
            Pointer<Uint8>,
            int,
            int,
            int,
          )
        >('cryptolib_molecular_seal')(
          pp,
          plaintext.length,
          cpw,
          pa,
          aad?.length ?? 0,
          ops,
          mem,
        ),
      );
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      calloc.free(cpw);
      if (pa != nullptr) {
        calloc.free(pa);
      }
    }
  }
}
