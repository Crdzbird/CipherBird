part of '../cryptolib.dart';

/// Symmetric operations.
extension CryptoLibSymmetric on CryptoLib {
  // ── Symmetric encryption ─────────────────────────────────────────────────

  /// Generate a 32-byte random symmetric key.
  Uint8List symKeygen() => _checkBufResult(_symKeygen());

  /// XChaCha20-Poly1305 encrypt.
  Uint8List xchacha20Encrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) {
    final pp = _toNative(plaintext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_xchacha20Enc(pp, plaintext.length, pk, key.length, pa, al));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// XChaCha20-Poly1305 decrypt.
  Uint8List xchacha20Decrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) {
    final pc = _toNative(ciphertext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_xchacha20Dec(pc, ciphertext.length, pk, key.length, pa, al));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// AES-256-GCM encrypt.
  Uint8List aes256gcmEncrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) {
    final pp = _toNative(plaintext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_aes256gcmEnc(pp, plaintext.length, pk, key.length, pa, al));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// AES-256-GCM decrypt.
  Uint8List aes256gcmDecrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) {
    final pc = _toNative(ciphertext);
    final pk = _toNative(key);
    Pointer<Uint8> pa = nullptr;
    int al = 0;
    if (aad != null && aad.isNotEmpty) {
      pa = _toNative(aad);
      al = aad.length;
    }
    try {
      return _checkBufResult(_aes256gcmDec(pc, ciphertext.length, pk, key.length, pa, al));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Check if AES-256-GCM is available on this CPU.
  bool aes256gcmAvailable() => _aes256gcmAvailable() != 0;

  // ── SecretStream ──────────────────────────────────────────────────────────

  /// Streaming encrypt: encrypt chunks of data with ordering.
  /// Returns (header, encryptedChunks).
  (Uint8List header, List<Uint8List> chunks) streamEncrypt(Uint8List key, List<Uint8List> plaintextChunks) {
    final pk = _toNative(key);
    final handle = _streamEncCreate(pk);
    calloc.free(pk);
    if (handle == nullptr) throw Exception('streamEncCreate failed');

    try {
      final headerResult = _streamEncHeader(handle);
      final header = _checkBufResult(headerResult);

      final encChunks = <Uint8List>[];
      for (int i = 0; i < plaintextChunks.length; i++) {
        final isLast = i == plaintextChunks.length - 1;
        final tag = isLast ? 3 : 0; // FINAL=3, MESSAGE=0
        final pp = _toNative(plaintextChunks[i]);
        try {
          final result = _streamEncPush(handle, pp, plaintextChunks[i].length, tag);
          encChunks.add(_checkBufResult(result));
        } finally {
          if (pp != nullptr) calloc.free(pp);
        }
      }
      return (header, encChunks);
    } finally {
      _streamEncFree(handle);
    }
  }

  /// Streaming decrypt: decrypt chunks of data.
  List<Uint8List> streamDecrypt(Uint8List key, Uint8List header, List<Uint8List> ciphertextChunks) {
    final pk = _toNative(key);
    final ph = _toNative(header);
    final handle = _streamDecCreate(pk, ph);
    calloc.free(pk);
    calloc.free(ph);
    if (handle == nullptr) throw Exception('streamDecCreate failed');

    try {
      final decChunks = <Uint8List>[];
      final outTag = calloc<Uint8>();
      for (final chunk in ciphertextChunks) {
        final pc = _toNative(chunk);
        try {
          final result = _streamDecPull(handle, pc, chunk.length, outTag);
          decChunks.add(_checkBufResult(result));
        } finally {
          if (pc != nullptr) calloc.free(pc);
        }
      }
      calloc.free(outTag);
      return decChunks;
    } finally {
      _streamDecFree(handle);
    }
  }


  /// Committing AEAD encrypt. Unlike a plain AEAD, the ciphertext binds the
  /// exact key, so it cannot be opened under a second key (no invisible
  /// salamander / partitioning-oracle attack). [key] is 32 bytes.
  Uint8List committingEncrypt(Uint8List plaintext, Uint8List key, [Uint8List? aad]) {
    final pp = _toNative(plaintext), pk = _toNative(key);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_committing_encrypt')(
              pp, plaintext.length, pk, key.length, pa, aad?.length ?? 0));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }

  /// Committing AEAD decrypt. Throws if the key/AAD don't match or the
  /// commitment check fails. [key] is 32 bytes.
  Uint8List committingDecrypt(Uint8List ciphertext, Uint8List key, [Uint8List? aad]) {
    final pc = _toNative(ciphertext), pk = _toNative(key);
    final pa = (aad != null && aad.isNotEmpty) ? _toNative(aad) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_committing_decrypt')(
              pc, ciphertext.length, pk, key.length, pa, aad?.length ?? 0));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (pk != nullptr) calloc.free(pk);
      if (pa != nullptr) calloc.free(pa);
    }
  }
}
