part of '../web_platform.dart';

/// Web view of the C `CryptoBuffer` struct.
final class CipherBirdBuffer extends Struct {
  const CipherBirdBuffer._(super.memory, super.base);

  static CipherBirdBuffer _new(Memory memory, int base) =>
      CipherBirdBuffer._(memory, base);

  /// Byte size under wasm32.
  static const int size = 8;

  Pointer<Uint8> get data => Pointer<Uint8>._(_memory.getU32(_base + 0));
  set data(Pointer<Uint8> value) => _memory.setU32(_base + 0, value.address);
  int get len => _memory.getU32(_base + 4);
  set len(int value) => _memory.setU32(_base + 4, value);
}
