part of '../cryptolib.dart';

/// EVM / Bitcoin interop: Keccak-256, RIPEMD-160 and secp256k1 ECDSA.
extension CryptoLibEvmBtc on CryptoLib {
  // ── EVM / Bitcoin interop (Keccak-256, RIPEMD-160, secp256k1 ECDSA) ────────

  /// Keccak-256 (ORIGINAL padding, Ethereum). 32-byte digest. NOT SHA3-256.
  /// Used for tx hashing, contract-address derivation, ABI selectors, EIP-55.
  Uint8List keccak256(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>(
          'cryptolib_keccak256')(pm, msg.length));
    } finally { if (pm != nullptr) calloc.free(pm); }
  }

  /// RIPEMD-160. 20-byte digest. Bitcoin HASH160(x) = ripemd160(sha256(x)).
  Uint8List ripemd160(Uint8List msg) {
    final pm = _toNative(msg);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, int)>(
          'cryptolib_ripemd160')(pm, msg.length));
    } finally { if (pm != nullptr) calloc.free(pm); }
  }

  /// secp256k1 keypair: secretKey(32) + publicKey(65 uncompressed, 0x04‖X‖Y).
  KeyPairResult secp256k1Keygen() => _extractKeyPair(
      _lib.lookupFunction<CryptoKeyPair Function(), CryptoKeyPair Function()>(
          'cryptolib_secp256k1_keygen')());

  /// Derive the public key from a 32-byte secret key.
  /// [compressed] true → 33 bytes (0x02/0x03‖X), false → 65 bytes (0x04‖X‖Y).
  Uint8List secp256k1Pubkey(Uint8List secretKey, {bool compressed = false}) {
    final sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Size, Int32),
          CryptoBufferResult Function(Pointer<Uint8>, int, int)>(
          'cryptolib_secp256k1_pubkey')(sp, secretKey.length, compressed ? 1 : 0));
    } finally { if (sp != nullptr) calloc.free(sp); }
  }

  /// Sign a 32-byte [digest] (RFC6979 deterministic, low-S). Returns 65 bytes:
  /// r(32)‖s(32)‖recovery_id(1). The caller hashes first (Ethereum:
  /// keccak256(rlp(tx)); Bitcoin: sha256(sha256(preimage))).
  Uint8List secp256k1Sign(Uint8List digest, Uint8List secretKey) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 sign: digest must be 32 bytes, got ${digest.length}');
    }
    final dp = _toNative(digest), sp = _toNative(secretKey);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>, Size),
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>, int)>(
          'cryptolib_secp256k1_sign')(dp, sp, secretKey.length));
    } finally { if (dp != nullptr) calloc.free(dp); if (sp != nullptr) calloc.free(sp); }
  }

  /// Verify a 64-byte [sig] (r‖s) over a 32-byte [digest]. [publicKey] is 33 or
  /// 65 bytes. Low-S enforced (EIP-2 / BIP-62). Returns true if valid.
  bool secp256k1Verify(Uint8List digest, Uint8List sig, Uint8List publicKey) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 verify: digest must be 32 bytes');
    }
    final dp = _toNative(digest), sgp = _toNative(sig), pp = _toNative(publicKey);
    try {
      return _lib.lookupFunction<
          Int32 Function(Pointer<Uint8>, Pointer<Uint8>, Size, Pointer<Uint8>, Size),
          int Function(Pointer<Uint8>, Pointer<Uint8>, int, Pointer<Uint8>, int)>(
          'cryptolib_secp256k1_verify')(dp, sgp, sig.length, pp, publicKey.length) == 1;
    } finally {
      if (dp != nullptr) calloc.free(dp);
      if (sgp != nullptr) calloc.free(sgp);
      if (pp != nullptr) calloc.free(pp);
    }
  }

  /// Recover the 65-byte uncompressed public key from a 32-byte [digest] and a
  /// 65-byte recoverable [sig65] (r‖s‖recovery_id). Ethereum's ecrecover.
  Uint8List secp256k1Recover(Uint8List digest, Uint8List sig65) {
    if (digest.length != 32) {
      throw ArgumentError('secp256k1 recover: digest must be 32 bytes');
    }
    if (sig65.length != 65) {
      throw ArgumentError('secp256k1 recover: signature must be 65 bytes (r‖s‖recid)');
    }
    final dp = _toNative(digest), sp = _toNative(sig65);
    try {
      return _checkBufResult(_lib.lookupFunction<
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>),
          CryptoBufferResult Function(Pointer<Uint8>, Pointer<Uint8>)>(
          'cryptolib_secp256k1_recover')(dp, sp));
    } finally { if (dp != nullptr) calloc.free(dp); if (sp != nullptr) calloc.free(sp); }
  }
}
