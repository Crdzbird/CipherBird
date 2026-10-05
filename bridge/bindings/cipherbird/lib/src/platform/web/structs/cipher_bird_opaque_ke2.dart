part of '../web_platform.dart';

/// Web view of the C `CryptoOpaqueKe2` struct.
final class CipherBirdOpaqueKe2 extends Struct {
  const CipherBirdOpaqueKe2._(super.memory, super.base);

  static CipherBirdOpaqueKe2 _new(Memory memory, int base) =>
      CipherBirdOpaqueKe2._(memory, base);

  /// Byte size under wasm32.
  static const int size = 20;

  CipherBirdBuffer get ke2 => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get serverState => CipherBirdBuffer._(_memory, _base + 8);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 16));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 16, value.address);
}
