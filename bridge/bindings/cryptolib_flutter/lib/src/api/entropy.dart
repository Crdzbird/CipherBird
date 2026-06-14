part of '../cryptolib.dart';

/// Entropy operations.
extension CryptoLibEntropy on CryptoLib {
  // ── Media Entropy ─────────────────────────────────────────────────────────

  /// Harvest entropy from a file (LavaRand mode).
  Pointer<Void> entropyFromFile(String path) {
    final cp = path.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFile(cp, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      calloc.free(cp);
      calloc.free(errPtr);
    }
  }

  /// Harvest entropy from a file (deterministic mode).
  Pointer<Void> entropyFromFileDeterministic(String path) {
    final cp = path.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFileDet(cp, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      calloc.free(cp);
      calloc.free(errPtr);
    }
  }

  /// Harvest entropy from multiple files (LavaRand mode).
  Pointer<Void> entropyFromFiles(List<String> paths) {
    final pathPtrs = calloc<Pointer<Utf8>>(paths.length);
    for (int i = 0; i < paths.length; i++) {
      pathPtrs[i] = paths[i].toNativeUtf8();
    }
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFiles(pathPtrs, paths.length, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      for (int i = 0; i < paths.length; i++) {
        calloc.free(pathPtrs[i]);
      }
      calloc.free(pathPtrs);
      calloc.free(errPtr);
    }
  }

  /// Harvest entropy from multiple files (deterministic mode).
  Pointer<Void> entropyFromFilesDeterministic(List<String> paths) {
    final pathPtrs = calloc<Pointer<Utf8>>(paths.length);
    for (int i = 0; i < paths.length; i++) {
      pathPtrs[i] = paths[i].toNativeUtf8();
    }
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropyFromFilesDet(pathPtrs, paths.length, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return h;
    } finally {
      for (int i = 0; i < paths.length; i++) {
        calloc.free(pathPtrs[i]);
      }
      calloc.free(pathPtrs);
      calloc.free(errPtr);
    }
  }

  /// Derive all 6 domain-separated keys at once.
  DerivedKeysResult entropyDeriveAll(Pointer<Void> handle) {
    final dk = _entropyDeriveAll(handle);
    return DerivedKeysResult(
      symmetricKey: _copyBuf(dk.symmetricKey),
      vaultMasterKey: _copyBuf(dk.vaultMasterKey),
      signingSeed: _copyBuf(dk.signingSeed),
      boxSeed: _copyBuf(dk.boxSeed),
      streamKey: _copyBuf(dk.streamKey),
      rawEntropy: _copyBuf(dk.rawEntropy),
    );
  }

  /// Derive a 32-byte symmetric key from an entropy handle.
  Uint8List entropySymmetricKey(Pointer<Void> handle) {
    return _checkBufResult(_entropySymKey(handle));
  }

  /// Get the 64-byte raw mixed entropy.
  Uint8List entropyRaw(Pointer<Void> handle) {
    return _checkBufResult(_entropyRaw(handle));
  }

  /// Get the 32-byte entropy boost key.
  Uint8List entropyBoost(Pointer<Void> handle) {
    return _checkBufResult(_entropyBoost(handle));
  }

  /// Get entropy info.
  EntropyInfoResult entropyInfo(Pointer<Void> handle) {
    final info = _entropyInfo(handle);
    final result = EntropyInfoResult(
      path: info.path.toDartString(),
      fileSize: info.fileSize,
      chunksRead: info.chunksRead,
      entropyBits: info.entropyBits,
    );
    _strFree(info.path);
    return result;
  }

  /// Get a full asymmetric bundle from entropy.
  AsymBundleResult entropyAsymBundle(Pointer<Void> handle) {
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final ab = _entropyAsymBundle(handle, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _strFree(errPtr.value);
        throw Exception(msg);
      }
      return _extractBundle(ab);
    } finally {
      calloc.free(errPtr);
    }
  }

  /// Refresh system entropy in-place.
  void entropyRefresh(Pointer<Void> handle) => _entropyRefresh(handle);

  /// Free an entropy handle.
  void entropyFree(Pointer<Void> handle) => _entropyFree(handle);

  // ── Entropy convenience ───────────────────────────────────────────────────

  /// One-liner: get a 32-byte key from any file.
  Uint8List keyFromFile(String path) {
    final cp = path.toNativeUtf8();
    try {
      return _checkBufResult(_keyFromFile(cp));
    } finally {
      calloc.free(cp);
    }
  }

  /// One-liner: encrypt plaintext using a file as the key.
  Packet sealFromFile(String path, String plaintext, String aad) {
    final cpath = path.toNativeUtf8();
    final cpt = plaintext.toNativeUtf8();
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _sealFromFile(cpath, cpt, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      calloc.free(cpath);
      calloc.free(cpt);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// One-liner: decrypt a packet using a file as the key.
  Uint8List openFromFile(String path, Packet pkt, String aad) {
    final cpath = path.toNativeUtf8();
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_openFromFile(cpath, cpkt, caad));
    } finally {
      calloc.free(cpath);
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

}
