part of '../cryptolib.dart';

/// Core operations.
extension CryptoLibCore on CryptoLib {
  // ── Init & version ────────────────────────────────────────────────────────

  /// Initialise libsodium. Call once at app start.
  void init() {
    if (_init() != 0) throw Exception('cryptolib: init failed');
  }

  /// Get the library version string.
  String version() => _version().toDartString();

  // ── Random bytes ──────────────────────────────────────────────────────────

  /// Generate n cryptographically secure random bytes.
  Uint8List randomBytes(int n) => _checkBufResult(_randomBytes(n));

  // ── Secure equal ──────────────────────────────────────────────────────────

  /// Constant-time comparison. Returns true if equal.
  bool secureEqual(Uint8List a, Uint8List b) {
    final pa = _toNative(a);
    final pb = _toNative(b);
    try {
      return _secureEqual(pa, a.length, pb, b.length) == 1;
    } finally {
      if (pa != nullptr) calloc.free(pa);
      if (pb != nullptr) calloc.free(pb);
    }
  }

}
