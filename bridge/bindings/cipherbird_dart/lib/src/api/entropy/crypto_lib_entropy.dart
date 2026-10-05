part of '../../cryptolib.dart';

/// Entropy operations.
extension CryptoLibEntropy on CryptoLib {
  /// Harvest entropy from a file (LavaRand mode).
  Pointer<Void> entropyFromFile(String path) {
    final cp = path.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final h = _entropy.entropyFromFile(cp, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
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
      final h = _entropy.entropyFromFileDet(cp, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
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
      final h = _entropy.entropyFromFiles(pathPtrs, paths.length, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
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
      final h = _entropy.entropyFromFilesDet(pathPtrs, paths.length, errPtr);
      if (errPtr.value != nullptr) {
        final msg = errPtr.value.toDartString();
        _core.strFree(errPtr.value);
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
}
