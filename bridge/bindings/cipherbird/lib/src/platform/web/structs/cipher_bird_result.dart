part of '../web_platform.dart';

/// Web view of the C `CryptoResult` struct.
final class CipherBirdResult extends Struct {
  const CipherBirdResult._(super.memory, super.base);

  static CipherBirdResult _new(Memory memory, int base) =>
      CipherBirdResult._(memory, base);

  /// Byte size under wasm32.
  static const int size = 8;

  int get ok => _memory.getI32(_base + 0);
  set ok(int value) => _memory.setI32(_base + 0, value);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 4));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 4, value.address);
}
