part of '../cryptolib.dart';

/// Vault operations.
extension CryptoLibVault on CryptoLib {
  // ── Vault ─────────────────────────────────────────────────────────────────

  /// Create a vault from a 32-byte master key.
  Pointer<Void> vaultCreate(Uint8List masterKey, {KdfPreset kdfPreset = KdfPreset.interactive}) {
    final pk = _toNative(masterKey);
    try {
      final h = _vaultCreate(pk, masterKey.length, kdfPreset.value);
      if (h == nullptr) throw Exception('cryptolib: vault create failed');
      return h;
    } finally {
      if (pk != nullptr) calloc.free(pk);
    }
  }

  /// Create a vault from an entropy handle.
  Pointer<Void> vaultFromEntropy(Pointer<Void> entropy, {KdfPreset kdf = KdfPreset.interactive}) {
    final h = _vaultFromEntropy(entropy, kdf.value);
    if (h == nullptr) throw Exception('cryptolib: vault from entropy failed');
    return h;
  }

  /// Seal plaintext through the vault pipeline.
  Packet vaultSeal(Pointer<Void> vault, Uint8List plaintext, String aad) {
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vaultSeal(vault, pp, plaintext.length, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Seal with entropy boost (two-factor).
  Packet vaultSealBoosted(Pointer<Void> vault, Uint8List plaintext, String aad, Pointer<Void> boost) {
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vaultSealBoosted(vault, pp, plaintext.length, caad, boost, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pp != nullptr) calloc.free(pp);
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Open a vault packet.
  Uint8List vaultOpen(Pointer<Void> vault, Packet pkt, String aad) {
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vaultOpen(vault, cpkt, caad));
    } finally {
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

  /// Open with entropy boost.
  Uint8List vaultOpenBoosted(Pointer<Void> vault, Packet pkt, String aad, Pointer<Void> boost) {
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vaultOpenBoosted(vault, cpkt, caad, boost));
    } finally {
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

  /// Get the vault's Ed25519 public key.
  Uint8List vaultPublicKey(Pointer<Void> vault) {
    return _checkBufResult(_vaultPublicKey(vault));
  }

  /// Serialise a packet to flat bytes.
  Uint8List packetSerialise(Packet pkt) {
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_packetSerialise(cpkt));
    } finally {
      _freePacketNative(cpkt);
    }
  }

  /// Deserialise flat bytes to a packet.
  Packet packetDeserialise(Uint8List data) {
    final pd = _toNative(data);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _packetDeserialise(pd, data.length, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pd != nullptr) calloc.free(pd);
      calloc.free(errPtr);
    }
  }

  /// Free a vault handle.
  void vaultFree(Pointer<Void> vault) => _vaultFree(vault);

}
