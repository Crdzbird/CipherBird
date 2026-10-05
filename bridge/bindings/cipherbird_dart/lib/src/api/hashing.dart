part of '../cryptolib.dart';

/// Hashing operations.
extension CryptoLibHashing on CryptoLib {
  /// BLAKE2b-512 hash. key may be empty for unkeyed.
  Uint8List blake2b(Uint8List msg, [Uint8List? key]) {
    final pm = _toNative(msg);
    Pointer<Uint8> pk = nullptr;
    int kl = 0;
    if (key != null && key.isNotEmpty) {
      pk = _toNative(key);
      kl = key.length;
    }
    try {
      return _checkBufResult(_hashing.blake2b(pm, msg.length, pk, kl));
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// SHA-256 hash.
  Uint8List sha256(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_hashing.sha256(pm, msg.length));
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
    }
  }

  /// SHA-512 hash.
  Uint8List sha512(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_hashing.sha512(pm, msg.length));
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
    }
  }

  /// HMAC-SHA512.
  Uint8List hmacSha512(Uint8List msg, Uint8List key) {
    final pm = _toNative(msg);
    final pk = _toNative(key);
    try {
      return _checkBufResult(
        _hashing.hmacSha512(pm, msg.length, pk, key.length),
      );
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// HMAC-SHA512 verify. Returns true if valid.
  bool hmacSha512Verify(Uint8List msg, Uint8List mac, Uint8List key) {
    final pm = _toNative(msg);
    final pmac = _toNative(mac);
    final pk = _toNative(key);
    try {
      return _hashing.hmacSha512Verify(
            pm,
            msg.length,
            pmac,
            mac.length,
            pk,
            key.length,
          ) ==
          1;
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pmac != nullptr) {
        calloc.free(pmac);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }
}
