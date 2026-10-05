part of '../../cipher_bird.dart';

/// Vault operations.
extension CipherBirdVaultManagement on CipherBird {
  /// Open with entropy boost.
  Uint8List vaultOpenBoosted(
    Pointer<Void> vault,
    Packet pkt,
    String aad,
    Pointer<Void> boost,
  ) {
    final caad = aad.toNativeUtf8();
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vault.vaultOpenBoosted(vault, cpkt, caad, boost));
    } finally {
      calloc.free(caad);
      _freePacketNative(cpkt);
    }
  }

  /// Get the vault's Ed25519 public key.
  Uint8List vaultPublicKey(Pointer<Void> vault) {
    return _checkBufResult(_vault.vaultPublicKey(vault));
  }

  /// Serialise a packet to flat bytes.
  Uint8List packetSerialise(Packet pkt) {
    final cpkt = _packetToNative(pkt);
    try {
      return _checkBufResult(_vault.packetSerialise(cpkt));
    } finally {
      _freePacketNative(cpkt);
    }
  }

  /// Deserialise flat bytes to a packet.
  Packet packetDeserialise(Uint8List data) {
    final pd = _toNative(data);
    final errPtr = calloc<Pointer<Utf8>>();
    try {
      final cp = _vault.packetDeserialise(pd, data.length, errPtr);
      return _extractPacket(cp, errPtr);
    } finally {
      if (pd != nullptr) {
        calloc.free(pd);
      }
      calloc.free(errPtr);
    }
  }

  /// Free a vault handle.
  void vaultFree(Pointer<Void> vault) => _vault.vaultFree(vault);
}
