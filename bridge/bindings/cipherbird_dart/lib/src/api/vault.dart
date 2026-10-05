part of '../cryptolib.dart';

/// Vault operations.
extension CryptoLibVault on CryptoLib {
  /// Create a vault from a 32-byte master key.
  Pointer<Void> vaultCreate(
    Uint8List masterKey, {
    KdfPreset kdfPreset = KdfPreset.interactive,
  }) {
    final pk = _toNative(masterKey);
    try {
      final h = _vault.vaultCreate(pk, masterKey.length, kdfPreset.value);
      if (h == nullptr) {
        throw Exception('cryptolib: vault create failed');
      }
      return h;
    } finally {
      if (pk != nullptr) {
        calloc.free(pk);
      }
    }
  }

  /// Create a vault from an entropy handle.
  Pointer<Void> vaultFromEntropy(
    Pointer<Void> entropy, {
    KdfPreset kdf = KdfPreset.interactive,
  }) {
    final h = _vault.vaultFromEntropy(entropy, kdf.value);
    if (h == nullptr) {
      throw Exception('cryptolib: vault from entropy failed');
    }
    return h;
  }

  /// Seal plaintext through the vault pipeline.
  Packet vaultSeal(Pointer<Void> vault, Uint8List plaintext, String aad) {
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vault.vaultSeal(vault, pp, plaintext.length, caad, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Seal with entropy boost (two-factor).
  Packet vaultSealBoosted(
    Pointer<Void> vault,
    Uint8List plaintext,
    String aad,
    Pointer<Void> boost,
  ) {
    final pp = _toNative(plaintext);
    final caad = aad.toNativeUtf8();
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vault.vaultSealBoosted(
        vault,
        pp,
        plaintext.length,
        caad,
        boost,
        errPtr,
      );
      return _extractPacket(cp, errPtr);
    } finally {
      if (pp != nullptr) {
        calloc.free(pp);
      }
      calloc.free(caad);
      calloc.free(errPtr);
    }
  }

  /// Open a vault packet.
  Uint8List vaultOpen(Pointer<Void> vault, Packet pkt, String aad) {
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vault.vaultOpen(vault, cpkt, caad));
    } finally {
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }
}
