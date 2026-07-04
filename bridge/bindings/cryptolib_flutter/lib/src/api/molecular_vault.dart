part of '../cryptolib.dart';

/// MolecularVault — maximum-assurance layered encryption.
///
/// A cascade of XChaCha20-Poly1305 ∘ AES-256-GCM-SIV under a key-committing
/// outer layer, keyed by Argon2id(passphrase) or a 32-byte full-entropy master
/// (e.g. from the hybrid KEM). Composition of vetted primitives only — no new
/// cryptography. Requires the native library built with OpenSSL.
extension CryptoLibMolecular on CryptoLib {
  /// Seal [plaintext] under a [passphrase]. [ops]/[mem] are the Argon2id work
  /// factors; pass 0 for either to use the library's SENSITIVE preset. Raise
  /// [mem] toward 1 << 30 (1 GiB) to make password guessing far costlier. The
  /// returned envelope is self-describing (carries the salt and parameters).
  Uint8List molecularSeal(Uint8List plaintext, String passphrase,
      {Uint8List? aad, int ops = 0, int mem = 0}) {
    final pp = _toNative(plaintext);
    final cpw = passphrase.toNativeUtf8();
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Utf8>,
              Pointer<Uint8>, Size, Uint64, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>,
              Pointer<Uint8>, int, int, int)>('cryptolib_molecular_seal')(
          pp, plaintext.length, cpw, pa, aad?.length ?? 0, ops, mem));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(cpw);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Open a passphrase-sealed envelope. A wrong passphrase, wrong [aad], or any
  /// tampering throws (fails closed) rather than returning garbage.
  Uint8List molecularOpen(Uint8List envelope, String passphrase, {Uint8List? aad}) {
    final pe = _toNative(envelope);
    final cpw = passphrase.toNativeUtf8();
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Utf8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Utf8>,
              Pointer<Uint8>, int)>('cryptolib_molecular_open')(
          pe, envelope.length, cpw, pa, aad?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      calloc.free(cpw);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Seal under a 32-byte full-entropy [masterKey] (e.g. a hybrid-KEM shared
  /// secret). No Argon2id is applied — the key is assumed to be full-entropy.
  Uint8List molecularSealWithKey(Uint8List plaintext, Uint8List masterKey,
      {Uint8List? aad}) {
    final pp = _toNative(plaintext);
    final pk = _toNative(masterKey);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>,
              Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('cryptolib_molecular_seal_with_key')(
          pp, plaintext.length, pk, masterKey.length, pa, aad?.length ?? 0));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Open a raw-key-sealed envelope.
  Uint8List molecularOpenWithKey(Uint8List envelope, Uint8List masterKey,
      {Uint8List? aad}) {
    final pe = _toNative(envelope);
    final pk = _toNative(masterKey);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>,
              Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int,
              Pointer<Uint8>, int)>('cryptolib_molecular_open_with_key')(
          pe, envelope.length, pk, masterKey.length, pa, aad?.length ?? 0));
    } finally {
      if (pe != nullptr) calloc.free(pe);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }
}
