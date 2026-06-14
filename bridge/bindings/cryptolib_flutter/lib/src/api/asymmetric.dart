part of '../cryptolib.dart';

/// Asymmetric operations.
extension CryptoLibAsymmetric on CryptoLib {
  // ── Ed25519 ───────────────────────────────────────────────────────────────

  /// Generate an Ed25519 signing keypair.
  KeyPairResult ed25519Keygen() => _extractKeyPair(_ed25519Keygen());

  /// Generate Ed25519 keypair from a 32-byte seed (deterministic).
  KeyPairResult ed25519KeygenFromSeed(Uint8List seed) {
    final ps = _toNative(seed);
    try {
      return _extractKeyPair(_ed25519KeygenFromSeed(ps, seed.length));
    } finally {
      if (ps != nullptr) calloc.free(ps);
    }
  }

  /// Sign a message. Returns 64-byte detached signature.
  Uint8List ed25519Sign(Uint8List msg, Uint8List secretKey) {
    final pm = _toNative(msg);
    final pk = _toNative(secretKey);
    try {
      return _checkBufResult(_ed25519Sign(pm, msg.length, pk, secretKey.length));
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Verify a detached signature. Returns true if valid.
  bool ed25519Verify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final pm = _toNative(msg);
    final ps = _toNative(sig);
    final pk = _toNative(publicKey);
    try {
      return _ed25519Verify(pm, msg.length, ps, sig.length, pk, publicKey.length) == 1;
    } finally {
      if (pm != nullptr) calloc.free(pm);
      if (ps != nullptr) calloc.free(ps);
      if (pk != nullptr) calloc.free(pk);
    }
  }

  // ── X25519 ────────────────────────────────────────────────────────────────

  /// Generate an X25519 key agreement keypair.
  KeyPairResult x25519Keygen() => _extractKeyPair(_x25519Keygen());

  /// Compute X25519 shared secret (32 bytes).
  Uint8List x25519SharedSecret(Uint8List ourSecret, Uint8List theirPublic) {
    final pos = _toNative(ourSecret);
    final ptp = _toNative(theirPublic);
    try {
      return _checkBufResult(_x25519SharedSecret(pos, ourSecret.length, ptp, theirPublic.length));
    } finally {
      if (pos != nullptr) calloc.free(pos);
      if (ptp != nullptr) calloc.free(ptp);
    }
  }

  // ── Box ───────────────────────────────────────────────────────────────────

  /// Generate a Box keypair (X25519).
  KeyPairResult boxKeygen() => _extractKeyPair(_boxKeygen());

  /// Box encrypt: sender to recipient authenticated encryption.
  Uint8List boxEncrypt(Uint8List plaintext, Uint8List recipientPub, Uint8List senderSec) {
    final pp = _toNative(plaintext);
    final prp = _toNative(recipientPub);
    final pss = _toNative(senderSec);
    try {
      return _checkBufResult(_boxEncrypt(pp, plaintext.length, prp, recipientPub.length, pss, senderSec.length));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (prp != nullptr) calloc.free(prp);
      if (pss != nullptr) calloc.free(pss);
    }
  }

  /// Box decrypt.
  Uint8List boxDecrypt(Uint8List ciphertext, Uint8List senderPub, Uint8List recipientSec) {
    final pc = _toNative(ciphertext);
    final psp = _toNative(senderPub);
    final prs = _toNative(recipientSec);
    try {
      return _checkBufResult(_boxDecrypt(pc, ciphertext.length, psp, senderPub.length, prs, recipientSec.length));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (psp != nullptr) calloc.free(psp);
      if (prs != nullptr) calloc.free(prs);
    }
  }

  // ── SealedBox ─────────────────────────────────────────────────────────────

  /// SealedBox encrypt (anonymous sender).
  Uint8List sealedboxEncrypt(Uint8List plaintext, Uint8List recipientPub) {
    final pp = _toNative(plaintext);
    final prp = _toNative(recipientPub);
    try {
      return _checkBufResult(_sealedboxEncrypt(pp, plaintext.length, prp, recipientPub.length));
    } finally {
      if (pp != nullptr) calloc.free(pp);
      if (prp != nullptr) calloc.free(prp);
    }
  }

  /// SealedBox decrypt.
  Uint8List sealedboxDecrypt(Uint8List ciphertext, Uint8List recipientPub, Uint8List recipientSec) {
    final pc = _toNative(ciphertext);
    final prp = _toNative(recipientPub);
    final prs = _toNative(recipientSec);
    try {
      return _checkBufResult(_sealedboxDecrypt(pc, ciphertext.length, prp, recipientPub.length, prs, recipientSec.length));
    } finally {
      if (pc != nullptr) calloc.free(pc);
      if (prp != nullptr) calloc.free(prp);
      if (prs != nullptr) calloc.free(prs);
    }
  }

}
