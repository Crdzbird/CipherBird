part of '../../cipher_bird.dart';

/// Hashing operations.
extension CipherBirdArgon2id on CipherBird {
  /// Hash a password to PHC string format.
  Uint8List argon2idHashStr(
    String password, {
    int ops = 2,
    int mem = 67108864,
  }) {
    final cp = password.toNativeUtf8();
    try {
      return _checkBufResult(_hashing.argon2idHashStr(cp, ops, mem));
    } finally {
      calloc.free(cp);
    }
  }

  /// Verify password against PHC string. Returns true if correct.
  bool argon2idVerifyStr(String password, String phcStr) {
    final cp = password.toNativeUtf8();
    final cphc = phcStr.toNativeUtf8();
    try {
      return _hashing.argon2idVerifyStr(cp, cphc) == 1;
    } finally {
      calloc.free(cp);
      calloc.free(cphc);
    }
  }

  /// Derive a key from password + salt.
  Uint8List argon2idDerive(
    String password,
    Uint8List salt, {
    int keyLen = 32,
    int ops = 2,
    int mem = 67108864,
  }) {
    final cp = password.toNativeUtf8();
    final ps = _toNative(salt);
    try {
      return _checkBufResult(
        _hashing.argon2idDerive(cp, ps, salt.length, keyLen, ops, mem),
      );
    } finally {
      calloc.free(cp);
      if (ps != nullptr) {
        calloc.free(ps);
      }
    }
  }
}
