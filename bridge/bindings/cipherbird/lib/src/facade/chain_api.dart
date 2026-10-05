part of '../cryptolib.dart';

/// EVM and Bitcoin interop primitives.
extension type ChainApi(CryptoLib _l) {
  /// Keccak-256 (ORIGINAL padding, Ethereum). 32-byte digest. NOT SHA3-256.
  /// Used for tx hashing, contract-address derivation, ABI selectors, EIP-55.
  Uint8List keccak256(Uint8List msg) => _l.keccak256(msg);

  /// RIPEMD-160. 20-byte digest. Bitcoin HASH160(x) = ripemd160(sha256(x)).
  Uint8List ripemd160(Uint8List msg) => _l.ripemd160(msg);

  /// secp256k1 keypair: secretKey(32) + publicKey(65 uncompressed, 0x04‖X‖Y).
  KeyPairResult secp256k1Keygen() => _l.secp256k1Keygen();

  /// Derive the public key from a 32-byte secret key.
  /// [compressed] true -> 33 bytes (0x02/0x03‖X), false -> 65 bytes (0x04‖X‖Y).
  Uint8List secp256k1Pubkey(Uint8List secretKey, {bool compressed = false}) =>
      _l.secp256k1Pubkey(secretKey, compressed: compressed);

  /// Sign a 32-byte [digest] (RFC6979 deterministic, low-S). Returns 65 bytes:
  /// r(32)‖s(32)‖recovery_id(1). The caller hashes first (Ethereum:
  /// keccak256(rlp(tx)); Bitcoin: sha256(sha256(preimage))).
  Uint8List secp256k1Sign(Uint8List digest, Uint8List secretKey) =>
      _l.secp256k1Sign(digest, secretKey);

  /// Verify a 64-byte [sig] (r‖s) over a 32-byte [digest]. [publicKey] is 33 or
  /// 65 bytes. Low-S enforced (EIP-2 / BIP-62). Returns true if valid.
  bool secp256k1Verify(Uint8List digest, Uint8List sig, Uint8List publicKey) =>
      _l.secp256k1Verify(digest, sig, publicKey);

  /// Recover the 65-byte uncompressed public key from a 32-byte [digest] and a
  /// 65-byte recoverable [sig65] (r‖s‖recovery_id). Ethereum's ecrecover.
  Uint8List secp256k1Recover(Uint8List digest, Uint8List sig65) =>
      _l.secp256k1Recover(digest, sig65);
}
