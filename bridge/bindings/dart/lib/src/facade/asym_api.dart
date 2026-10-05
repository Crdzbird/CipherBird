part of '../../cryptolib_ffi.dart';

/// X25519 key exchange, Ed25519 signing, boxes and sealed boxes.
extension type AsymApi(CryptoLib _l) {
  /// Generate an Ed25519 signing keypair.
  KeyPairResult ed25519Keygen() => _l.ed25519Keygen();

  /// Generate Ed25519 keypair from a 32-byte seed (deterministic).
  KeyPairResult ed25519KeygenFromSeed(Uint8List seed) =>
      _l.ed25519KeygenFromSeed(seed);

  /// Sign a message. Returns 64-byte detached signature.
  Uint8List ed25519Sign(Uint8List msg, Uint8List secretKey) =>
      _l.ed25519Sign(msg, secretKey);

  /// Verify a detached signature. Returns true if valid.
  bool ed25519Verify(Uint8List msg, Uint8List sig, Uint8List publicKey) =>
      _l.ed25519Verify(msg, sig, publicKey);

  /// Generate an X25519 key agreement keypair.
  KeyPairResult x25519Keygen() => _l.x25519Keygen();

  /// Compute X25519 shared secret (32 bytes).
  Uint8List x25519SharedSecret(Uint8List ourSecret, Uint8List theirPublic) =>
      _l.x25519SharedSecret(ourSecret, theirPublic);

  /// Generate a Box keypair (X25519).
  KeyPairResult boxKeygen() => _l.boxKeygen();

  /// Box encrypt: sender to recipient authenticated encryption.
  Uint8List boxEncrypt(
          Uint8List plaintext, Uint8List recipientPub, Uint8List senderSec) =>
      _l.boxEncrypt(plaintext, recipientPub, senderSec);

  /// Box decrypt.
  Uint8List boxDecrypt(
          Uint8List ciphertext, Uint8List senderPub, Uint8List recipientSec) =>
      _l.boxDecrypt(ciphertext, senderPub, recipientSec);

  /// SealedBox encrypt (anonymous sender).
  Uint8List sealedboxEncrypt(Uint8List plaintext, Uint8List recipientPub) =>
      _l.sealedboxEncrypt(plaintext, recipientPub);

  /// SealedBox decrypt.
  Uint8List sealedboxDecrypt(Uint8List ciphertext, Uint8List recipientPub,
          Uint8List recipientSec) =>
      _l.sealedboxDecrypt(ciphertext, recipientPub, recipientSec);
}
