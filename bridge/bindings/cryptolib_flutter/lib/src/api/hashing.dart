part of '../cryptolib.dart';

/// Hashing operations.
extension CryptoLibHashing on CryptoLib {
  // ── Hashing ───────────────────────────────────────────────────────────────

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
      return _checkBufResult(_blake2b(pm, msg.length, pk, kl));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// SHA-256 hash.
  Uint8List sha256(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_sha256(pm, msg.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
    }
  }

  /// SHA-512 hash.
  Uint8List sha512(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_sha512(pm, msg.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
    }
  }

  /// HMAC-SHA512.
  Uint8List hmacSha512(Uint8List msg, Uint8List key) {
    final pm = _toNative(msg);
    final pk = _toNative(key);
    try {
      return _checkBufResult(_hmacSha512(pm, msg.length, pk, key.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HMAC-SHA512 verify. Returns true if valid.
  bool hmacSha512Verify(Uint8List msg, Uint8List mac, Uint8List key) {
    final pm = _toNative(msg);
    final pmac = _toNative(mac);
    final pk = _toNative(key);
    try {
      return _hmacSha512Verify(pm, msg.length, pmac, mac.length, pk, key.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pmac != nullptr) calloc.free(pmac);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  // ── Argon2id ──────────────────────────────────────────────────────────────

  /// Hash a password to PHC string format.
  Uint8List argon2idHashStr(String password, {int ops = 2, int mem = 67108864}) {
    final cp = password.toNativeUtf8();
    try {
      return _checkBufResult(_argon2idHashStr(cp, ops, mem));
    } finally {
      calloc.free(cp);
    }
  }

  /// Verify password against PHC string. Returns true if correct.
  bool argon2idVerifyStr(String password, String phcStr) {
    final cp = password.toNativeUtf8();
    final cphc = phcStr.toNativeUtf8();
    try {
      return _argon2idVerifyStr(cp, cphc) == 1;
    } finally {
      calloc.free(cp);
      calloc.free(cphc);
    }
  }

  /// Derive a key from password + salt.
  Uint8List argon2idDerive(String password, Uint8List salt,
      {int keyLen = 32, int ops = 2, int mem = 67108864}) {
    final cp = password.toNativeUtf8();
    final ps = _toNative(salt);
    try {
      return _checkBufResult(_argon2idDerive(cp, ps, salt.length, keyLen, ops, mem));
    } finally {
      calloc.free(cp);
      if (ps != nullptr) calloc.free(ps);
    }
  }


  /// BLAKE3 hash. [outLen] is the extendable output length in bytes
  /// (defaults to 32). Pass a larger value to use BLAKE3 as an XOF.
  Uint8List blake3(Uint8List msg, {int outLen = 32}) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, int)>(
          'cryptolib_blake3')(pm, msg.length, outLen));
    } finally {
      if (pm != nullptr) calloc.free(pm);
    }
  }

  /// BLAKE3 keyed MAC. [key] must be exactly 32 bytes. [outLen] defaults to 32.
  Uint8List blake3Keyed(Uint8List msg, Uint8List key, {int outLen = 32}) {
    if (key.length != 32) {
      throw ArgumentError('BLAKE3 keyed MAC requires a 32-byte key, got ${key.length}');
    }
    final pm = _toNative(msg);
    final pk = _toNative(key);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_blake3_keyed')(pm, msg.length, pk, key.length, outLen));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// BLAKE3 key derivation. [context] is a hard-coded, application-unique
  /// domain-separation string; [ikm] is the input key material. [outLen]
  /// defaults to 32.
  Uint8List blake3DeriveKey(String context, Uint8List ikm, {int outLen = 32}) {
    final cc = context.toNativeUtf8();
    final pk = _toNative(ikm);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Utf8>, Pointer<Uint8>, int, int)>(
          'cryptolib_blake3_derive_key')(cc, pk, ikm.length, outLen));
    } finally {
      calloc.free(cc);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HMAC-SHA256. [key] should be >= 32 bytes. Returns a 32-byte tag.
  Uint8List hmacSha256(Uint8List msg, Uint8List key) {
    final pm = _toNative(msg), pk = _toNative(key);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hmac_sha256')(pm, msg.length, pk, key.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Verify an HMAC-SHA256 tag in constant time. Returns true if valid.
  bool hmacSha256Verify(Uint8List msg, Uint8List mac, Uint8List key) {
    final pm = _toNative(msg), pmac = _toNative(mac), pk = _toNative(key);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hmac_sha256_verify')(
              pm, msg.length, pmac, mac.length, pk, key.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pmac != nullptr) calloc.free(pmac);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HKDF-SHA256 extract: PRK = HMAC(salt, IKM). Pass an empty [salt] for the
  /// all-zero default. Returns a 32-byte pseudorandom key.
  Uint8List hkdfExtract(Uint8List ikm, {Uint8List? salt}) {
    final ps = (salt != null && salt.isNotEmpty) ? _toNative(salt) : nullptr;
    final pk = _toNative(ikm);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_hkdf_extract')(ps, salt?.length ?? 0, pk, ikm.length));
    } finally {
      if (ps != nullptr) calloc.free(ps);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// HKDF-SHA256 expand: derive [outLen] bytes of output key material from a
  /// pseudorandom key [prk] and optional [info] context.
  Uint8List hkdfExpand(Uint8List prk, {Uint8List? info, int outLen = 32}) {
    final pp = _toNative(prk);
    final pi = (info != null && info.isNotEmpty) ? _toNative(info) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_hkdf_expand')(pp, prk.length, pi, info?.length ?? 0, outLen));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (pi != nullptr) calloc.free(pi);
    }
  }

  /// HKDF-SHA256 one-shot (extract + expand): derive [outLen] bytes from [ikm]
  /// with optional [salt] and [info].
  Uint8List hkdfDerive(Uint8List ikm,
      {Uint8List? salt, Uint8List? info, int outLen = 32}) {
    final pk = _toNative(ikm);
    final ps = (salt != null && salt.isNotEmpty) ? _toNative(salt) : nullptr;
    final pi = (info != null && info.isNotEmpty) ? _toNative(info) : nullptr;
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(
              Pointer<Uint8>, Size, Pointer<Uint8>, Size, Pointer<Uint8>, Size, Size),
          CryptoBufferResult Function(
              Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int, int)>(
          'cryptolib_hkdf_derive')(
              pk, ikm.length, ps, salt?.length ?? 0, pi, info?.length ?? 0, outLen));
    } finally {
      if (pk != nullptr) calloc.free(pk);
      if (ps != nullptr) calloc.free(ps);
      if (pi != nullptr) calloc.free(pi);
    }
  }
}
