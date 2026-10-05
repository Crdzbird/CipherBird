part of '../../cryptolib.dart';

/// Stego operations.
extension CryptoLibStego on CryptoLib {
  /// Embed raw bytes into a media file.
  void stegoEmbed(String coverPath, Uint8List payload, String outputPath) {
    final cc = coverPath.toNativeUtf8();
    final pp = _toNative(payload);
    final co = outputPath.toNativeUtf8();
    try {
      final r = _stego.stegoEmbed(cc, pp, payload.length, co);
      _checkResult(r);
    } finally {
      calloc.free(cc);
      if (pp != nullptr) {
        calloc.free(pp);
      }
      calloc.free(co);
    }
  }

  /// Extract raw bytes from a stego media file.
  Uint8List stegoExtract(String stegoPath) {
    final cp = stegoPath.toNativeUtf8();
    try {
      return _checkBufResult(_stego.stegoExtract(cp));
    } finally {
      calloc.free(cp);
    }
  }

  /// Get the steganographic capacity of a cover file (in bytes).
  int stegoCapacity(String coverPath) {
    final cp = coverPath.toNativeUtf8();
    try {
      return _stego.stegoCapacity(cp);
    } finally {
      calloc.free(cp);
    }
  }
}
