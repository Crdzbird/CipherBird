part of '../cipher_bird.dart';

/// Core operations.
extension CipherBirdCore on CipherBird {
  /// Initialise libsodium. Call once at app start.
  void init() {
    if (_core.init() != 0) {
      throw Exception('cipherbird: init failed');
    }
  }

  /// Get the library version string.
  String version() => _core.version().toDartString();

  /// Generate n cryptographically secure random bytes.
  Uint8List randomBytes(int n) => _checkBufResult(_core.randomBytes(n));

  /// Constant-time comparison. Returns true if equal.
  bool secureEqual(Uint8List a, Uint8List b) {
    final pa = _toNative(a);
    final pb = _toNative(b);
    try {
      return _core.secureEqual(pa, a.length, pb, b.length) == 1;
    } finally {
      if (pa != nullptr) {
        calloc.free(pa);
      }
      if (pb != nullptr) {
        calloc.free(pb);
      }
    }
  }
}
