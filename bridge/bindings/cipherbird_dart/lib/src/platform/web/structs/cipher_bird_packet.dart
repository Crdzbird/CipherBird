part of '../web_platform.dart';

/// Web view of the C `CryptoPacket` struct.
final class CipherBirdPacket extends Struct {
  const CipherBirdPacket._(super.memory, super.base);

  static CipherBirdPacket _new(Memory memory, int base) =>
      CipherBirdPacket._(memory, base);

  /// Byte size under wasm32.
  static const int size = 24;

  CipherBirdBuffer get ciphertext => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get signature => CipherBirdBuffer._(_memory, _base + 8);
  CipherBirdBuffer get kdfSalt => CipherBirdBuffer._(_memory, _base + 16);
}
