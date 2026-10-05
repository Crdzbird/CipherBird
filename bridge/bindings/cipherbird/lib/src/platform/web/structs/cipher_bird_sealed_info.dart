part of '../web_platform.dart';

/// Web view of the C `CryptoSealedInfo` struct.
final class CipherBirdSealedInfo extends Struct {
  const CipherBirdSealedInfo._(super.memory, super.base);

  static CipherBirdSealedInfo _new(Memory memory, int base) =>
      CipherBirdSealedInfo._(memory, base);

  /// Byte size under wasm32.
  static const int size = 24;

  int get ok => _memory.getU8(_base + 0);
  set ok(int value) => _memory.setU8(_base + 0, value);
  int get version => _memory.getU8(_base + 1);
  set version(int value) => _memory.setU8(_base + 1, value);
  int get suite => _memory.getU8(_base + 2);
  set suite(int value) => _memory.setU8(_base + 2, value);
  int get streaming => _memory.getU8(_base + 3);
  set streaming(int value) => _memory.setU8(_base + 3, value);
  Array<Uint8> get fingerprint => Array<Uint8>._(_memory, _base + 4, 16);
  int get kemCiphertextLen => _memory.getU32(_base + 20);
  set kemCiphertextLen(int value) => _memory.setU32(_base + 20, value);
}
