part of '../../cipher_bird.dart';

/// Password hashing with the password as a [String]. A Dart string cannot be
/// wiped; the temporary UTF-8 copy and the native copy are. Prefer the byte
/// forms in [CipherBirdArgon2id] for passwords you hold as bytes.
extension CipherBirdArgon2idText on CipherBird {
  /// Hash a password to PHC string format.
  Uint8List argon2idHashStr(
    String password, {
    int ops = 2,
    int mem = 67108864,
  }) {
    final bytes = utf8.encode(password);
    try {
      return argon2idHashStrBytes(bytes, ops: ops, mem: mem);
    } finally {
      bytes.wipe();
    }
  }

  /// Verify password against PHC string. Returns true if correct.
  bool argon2idVerifyStr(String password, String phcStr) {
    final bytes = utf8.encode(password);
    try {
      return argon2idVerifyStrBytes(bytes, phcStr);
    } finally {
      bytes.wipe();
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
    final bytes = utf8.encode(password);
    try {
      return argon2idDeriveBytes(
        bytes,
        salt,
        keyLen: keyLen,
        ops: ops,
        mem: mem,
      );
    } finally {
      bytes.wipe();
    }
  }
}
