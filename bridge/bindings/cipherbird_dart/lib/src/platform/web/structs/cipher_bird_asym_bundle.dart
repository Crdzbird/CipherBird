part of '../web_platform.dart';

/// Web view of the C `CryptoAsymBundle` struct.
final class CipherBirdAsymBundle extends Struct {
  const CipherBirdAsymBundle._(super.memory, super.base);

  static CipherBirdAsymBundle _new(Memory memory, int base) =>
      CipherBirdAsymBundle._(memory, base);

  /// Byte size under wasm32.
  static const int size = 32;

  CipherBirdBuffer get boxPublic => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get boxSecret => CipherBirdBuffer._(_memory, _base + 8);
  CipherBirdBuffer get signPublic => CipherBirdBuffer._(_memory, _base + 16);
  CipherBirdBuffer get signSecret => CipherBirdBuffer._(_memory, _base + 24);
}
