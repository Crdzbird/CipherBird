part of '../cipher_bird.dart';

/// Asymmetric operations.
extension CipherBirdAsymmetric on CipherBird {
  /// Generate an Ed25519 signing keypair.
  KeyPairResult ed25519Keygen() => _extractKeyPair(_asymmetric.ed25519Keygen());

  /// Generate Ed25519 keypair from a 32-byte seed (deterministic).
  KeyPairResult ed25519KeygenFromSeed(Uint8List seed) {
    final ps = _toNative(seed);
    try {
      return _extractKeyPair(
        _asymmetric.ed25519KeygenFromSeed(ps, seed.length),
      );
    } finally {
      if (ps != nullptr) {
        calloc.free(ps);
      }
    }
  }

  /// Sign a message. Returns 64-byte detached signature.
  Uint8List ed25519Sign(Uint8List msg, Uint8List secretKey) {
    final pm = _toNative(msg);
    final pk = _toNative(secretKey);
    try {
      return _checkBufResult(
        _asymmetric.ed25519Sign(pm, msg.length, pk, secretKey.length),
      );
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// Verify a detached signature. Returns true if valid.
  bool ed25519Verify(Uint8List msg, Uint8List sig, Uint8List publicKey) {
    final pm = _toNative(msg);
    final ps = _toNative(sig);
    final pk = _toNative(publicKey);
    try {
      return _asymmetric.ed25519Verify(
            pm,
            msg.length,
            ps,
            sig.length,
            pk,
            publicKey.length,
          ) ==
          1;
    } finally {
      if (pm != nullptr) {
        calloc.free(pm);
      }
      if (ps != nullptr) {
        calloc.free(ps);
      }
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// Generate an X25519 key agreement keypair.
  KeyPairResult x25519Keygen() => _extractKeyPair(_asymmetric.x25519Keygen());

  /// Compute X25519 shared secret (32 bytes).
  Uint8List x25519SharedSecret(Uint8List ourSecret, Uint8List theirPublic) {
    final pos = _toNative(ourSecret);
    final ptp = _toNative(theirPublic);
    try {
      return _checkBufResult(
        _asymmetric.x25519SharedSecret(
          pos,
          ourSecret.length,
          ptp,
          theirPublic.length,
        ),
      );
    } finally {
      if (pos != nullptr) {
        calloc.free(pos);
      }
      if (ptp != nullptr) {
        calloc.free(ptp);
      }
    }
  }

  /// Generate a Box keypair (X25519).
  KeyPairResult boxKeygen() => _extractKeyPair(_asymmetric.boxKeygen());
}
