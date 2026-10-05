part of '../cryptolib.dart';

/// Hashes, MACs, password hashing and HKDF.
extension type HashApi(CryptoLib _l) {
  /// Incremental BLAKE3; pass a 32-byte [key] for keyed (MAC) mode.
  Blake3Hasher blake3Hasher({Uint8List? key}) => _l.blake3Hasher(key: key);

  /// BLAKE2b-512 hash. key may be empty for unkeyed.
  Uint8List blake2b(Uint8List msg, [Uint8List? key]) => _l.blake2b(msg, key);

  /// SHA-256 hash.
  Uint8List sha256(Uint8List msg) => _l.sha256(msg);

  /// SHA-512 hash.
  Uint8List sha512(Uint8List msg) => _l.sha512(msg);

  /// HMAC-SHA512.
  Uint8List hmacSha512(Uint8List msg, Uint8List key) => _l.hmacSha512(msg, key);

  /// HMAC-SHA512 verify. Returns true if valid.
  bool hmacSha512Verify(Uint8List msg, Uint8List mac, Uint8List key) =>
      _l.hmacSha512Verify(msg, mac, key);

  /// Hash a password to PHC string format.
  Uint8List argon2idHashStr(
    String password, {
    int ops = 2,
    int mem = 67108864,
  }) => _l.argon2idHashStr(password, ops: ops, mem: mem);

  /// Verify password against PHC string. Returns true if correct.
  bool argon2idVerifyStr(String password, String phcStr) =>
      _l.argon2idVerifyStr(password, phcStr);

  /// Derive a key from password + salt.
  Uint8List argon2idDerive(
    String password,
    Uint8List salt, {
    int keyLen = 32,
    int ops = 2,
    int mem = 67108864,
  }) => _l.argon2idDerive(password, salt, keyLen: keyLen, ops: ops, mem: mem);

  /// BLAKE3 hash. [outLen] is the extendable output length in bytes
  /// (defaults to 32). Pass a larger value to use BLAKE3 as an XOF.
  Uint8List blake3(Uint8List msg, {int outLen = 32}) =>
      _l.blake3(msg, outLen: outLen);

  /// BLAKE3 keyed MAC. [key] must be exactly 32 bytes. [outLen] defaults to 32.
  Uint8List blake3Keyed(Uint8List msg, Uint8List key, {int outLen = 32}) =>
      _l.blake3Keyed(msg, key, outLen: outLen);

  /// BLAKE3 key derivation. [context] is a hard-coded, application-unique
  /// domain-separation string; [ikm] is the input key material. [outLen]
  /// defaults to 32.
  Uint8List blake3DeriveKey(String context, Uint8List ikm, {int outLen = 32}) =>
      _l.blake3DeriveKey(context, ikm, outLen: outLen);

  /// HMAC-SHA256. [key] should be >= 32 bytes. Returns a 32-byte tag.
  Uint8List hmacSha256(Uint8List msg, Uint8List key) => _l.hmacSha256(msg, key);

  /// Verify an HMAC-SHA256 tag in constant time. Returns true if valid.
  bool hmacSha256Verify(Uint8List msg, Uint8List mac, Uint8List key) =>
      _l.hmacSha256Verify(msg, mac, key);

  /// HKDF-SHA256 extract: PRK = HMAC(salt, IKM). Pass an empty [salt] for the
  /// all-zero default. Returns a 32-byte pseudorandom key.
  Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) =>
      _l.hkdfExtract(ikm, salt: salt);

  /// HKDF-SHA256 expand: derive [outLen] bytes of output key material from a
  /// pseudorandom key [prk] and optional [info] context.
  Uint8List hkdfExpand(Uint8List prk, {Uint8List? info, int outLen = 32}) =>
      _l.hkdfExpand(prk, info: info, outLen: outLen);

  /// HKDF-SHA256 one-shot (extract + expand): derive [outLen] bytes from [ikm]
  /// with optional [salt] and [info].
  Uint8List hkdfDerive(
    Uint8List ikm, {
    Uint8List? salt,
    Uint8List? info,
    int outLen = 32,
  }) => _l.hkdfDerive(ikm, salt: salt, info: info, outLen: outLen);
}
