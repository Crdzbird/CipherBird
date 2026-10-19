part of '../../cipher_bird.dart';

/// Password hashing with the password given as UTF-8 bytes, so the caller
/// can wipe it afterwards; the native copies are wiped on free.
extension CipherBirdArgon2id on CipherBird {
  /// Hash a password to PHC string format.
  Uint8List argon2idHashStrBytes(
    Uint8List password, {
    int ops = 2,
    int mem = 67108864,
  }) {
    final cp = _toNativeZ(password);
    try {
      return _checkBufResult(_hashing.argon2idHashStr(cp, ops, mem));
    } finally {
      calloc.free(cp);
    }
  }

  /// Verify a password against a PHC string. Returns true if correct.
  bool argon2idVerifyStrBytes(Uint8List password, String phcStr) {
    final cp = _toNativeZ(password);
    final cphc = phcStr.toNativeUtf8();
    try {
      return _hashing.argon2idVerifyStr(cp, cphc) == 1;
    } finally {
      calloc.free(cp);
      calloc.free(cphc);
    }
  }

  /// Derive a key from password + salt.
  Uint8List argon2idDeriveBytes(
    Uint8List password,
    Uint8List salt, {
    int keyLen = 32,
    int ops = 2,
    int mem = 67108864,
  }) {
    final cp = _toNativeZ(password);
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
