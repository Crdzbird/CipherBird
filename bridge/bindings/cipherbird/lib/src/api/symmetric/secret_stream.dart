part of '../../cryptolib.dart';

/// Symmetric operations.
extension CryptoLibSecretStream on CryptoLib {
  /// Streaming encrypt: encrypt chunks of data with ordering.
  /// Returns (header, encryptedChunks).
  (Uint8List header, List<Uint8List> chunks) streamEncrypt(
    Uint8List key,
    List<Uint8List> plaintextChunks,
  ) {
    final pk = _toNative(key);
    final handle = _symmetric.streamEncCreate(pk);
    calloc.free(pk);
    if (handle == nullptr) {
      throw Exception('streamEncCreate failed');
    }

    try {
      final headerResult = _symmetric.streamEncHeader(handle);
      final header = _checkBufResult(headerResult);

      final encChunks = <Uint8List>[];
      for (int i = 0; i < plaintextChunks.length; i++) {
        final isLast = i == plaintextChunks.length - 1;
        final tag = isLast ? 3 : 0;
        final pp = _toNative(plaintextChunks[i]);
        try {
          final result = _symmetric.streamEncPush(
            handle,
            pp,
            plaintextChunks[i].length,
            tag,
          );
          encChunks.add(_checkBufResult(result));
        } finally {
          if (pp != nullptr) {
            calloc.free(pp);
          }
        }
      }
      return (header, encChunks);
    } finally {
      _symmetric.streamEncFree(handle);
    }
  }

  /// Streaming decrypt: decrypt chunks of data.
  List<Uint8List> streamDecrypt(
    Uint8List key,
    Uint8List header,
    List<Uint8List> ciphertextChunks,
  ) {
    final pk = _toNative(key);
    final ph = _toNative(header);
    final handle = _symmetric.streamDecCreate(pk, ph);
    calloc.free(pk);
    calloc.free(ph);
    if (handle == nullptr) {
      throw Exception('streamDecCreate failed');
    }

    try {
      final decChunks = <Uint8List>[];
      final outTag = calloc<Uint8>();
      for (final chunk in ciphertextChunks) {
        final pc = _toNative(chunk);
        try {
          final result = _symmetric.streamDecPull(
            handle,
            pc,
            chunk.length,
            outTag,
          );
          decChunks.add(_checkBufResult(result));
        } finally {
          if (pc != nullptr) {
            calloc.free(pc);
          }
        }
      }
      calloc.free(outTag);
      return decChunks;
    } finally {
      _symmetric.streamDecFree(handle);
    }
  }
}
