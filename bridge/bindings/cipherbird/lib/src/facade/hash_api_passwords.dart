part of '../cipher_bird.dart';

/// Password hashing with the password as bytes the caller can wipe.
extension HashApiPasswords on HashApi {
  /// Hash a password to PHC string format.
  Uint8List argon2idHashStrBytes(
    Uint8List password, {
    int ops = 2,
    int mem = 67108864,
  }) => _l.argon2idHashStrBytes(password, ops: ops, mem: mem);

  /// Verify a password against a PHC string. Returns true if correct.
  bool argon2idVerifyStrBytes(Uint8List password, String phcStr) =>
      _l.argon2idVerifyStrBytes(password, phcStr);

  /// Derive a key from password + salt.
  Uint8List argon2idDeriveBytes(
    Uint8List password,
    Uint8List salt, {
    int keyLen = 32,
    int ops = 2,
    int mem = 67108864,
  }) => _l.argon2idDeriveBytes(
    password,
    salt,
    keyLen: keyLen,
    ops: ops,
    mem: mem,
  );
}
