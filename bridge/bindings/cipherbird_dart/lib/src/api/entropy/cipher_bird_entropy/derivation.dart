part of '../../../cipher_bird.dart';

/// Entropy operations.
extension CipherBirdEntropyDerivation on CipherBird {
  /// Derive all 6 domain-separated keys at once.
  DerivedKeysResult entropyDeriveAll(Pointer<Void> handle) {
    final dk = _entropy.entropyDeriveAll(handle);
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
    return _checkBufResult(_entropy.entropySymKey(handle));
  }

  /// Get the 64-byte raw mixed entropy.
  Uint8List entropyRaw(Pointer<Void> handle) {
    return _checkBufResult(_entropy.entropyRaw(handle));
  }

  /// Get the 32-byte entropy boost key.
  Uint8List entropyBoost(Pointer<Void> handle) {
    return _checkBufResult(_entropy.entropyBoost(handle));
  }

  /// Get entropy info.
  EntropyInfoResult entropyInfo(Pointer<Void> handle) {
    final info = _entropy.entropyInfo(handle);
    final result = EntropyInfoResult(
      path: info.path.toDartString(),
      fileSize: info.fileSize,
      chunksRead: info.chunksRead,
      entropyBits: info.entropyBits,
    );
    _core.strFree(info.path);
    return result;
  }

  /// Get a full asymmetric bundle from entropy.
  AsymBundleResult entropyAsymBundle(Pointer<Void> handle) {
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final ab = _entropy.entropyAsymBundle(handle, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
        throw Exception(msg);
      }
      return _extractBundle(ab);
    } finally {
      calloc.free(errPtr);
    }
  }

  /// Refresh system entropy in-place.
  void entropyRefresh(Pointer<Void> handle) => _entropy.entropyRefresh(handle);

  /// Free an entropy handle.
  void entropyFree(Pointer<Void> handle) => _entropy.entropyFree(handle);

  /// One-liner: get a 32-byte key from any file.
  Uint8List keyFromFile(String path) {
    final cp = path.toNativeUtf8();
    try {
      return _checkBufResult(_entropy.keyFromFile(cp));
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
      final cp = _entropy.sealFromFile(cpath, cpt, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      calloc.free(cpath);
      calloc.free(cpt);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }
}
