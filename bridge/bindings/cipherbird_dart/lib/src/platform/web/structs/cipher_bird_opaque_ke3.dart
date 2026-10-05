part of '../web_platform.dart';

/// Web view of the C `CryptoOpaqueKe3` struct.
final class CipherBirdOpaqueKe3 extends Struct {
  const CipherBirdOpaqueKe3._(super.memory, super.base);

  static CipherBirdOpaqueKe3 _new(Memory memory, int base) =>
      CipherBirdOpaqueKe3._(memory, base);

  /// Byte size under wasm32.
  static const int size = 28;

  CipherBirdBuffer get ke3 => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get sessionKey => CipherBirdBuffer._(_memory, _base + 8);
  CipherBirdBuffer get exportKey => CipherBirdBuffer._(_memory, _base + 16);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 24));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 24, value.address);
}
