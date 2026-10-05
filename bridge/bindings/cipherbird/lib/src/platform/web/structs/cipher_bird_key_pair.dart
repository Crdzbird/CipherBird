part of '../web_platform.dart';

/// Web view of the C `CryptoKeyPair` struct.
final class CipherBirdKeyPair extends Struct {
  const CipherBirdKeyPair._(super.memory, super.base);

  static CipherBirdKeyPair _new(Memory memory, int base) =>
      CipherBirdKeyPair._(memory, base);

  /// Byte size under wasm32.
  static const int size = 16;

  CipherBirdBuffer get publicKey => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get secretKey => CipherBirdBuffer._(_memory, _base + 8);
}
