part of '../web_platform.dart';

/// Web view of the C `CryptoOprfBlind` struct.
final class CipherBirdOprfBlind extends Struct {
  const CipherBirdOprfBlind._(super.memory, super.base);

  static CipherBirdOprfBlind _new(Memory memory, int base) =>
      CipherBirdOprfBlind._(memory, base);

  /// Byte size under wasm32.
  static const int size = 20;

  CipherBirdBuffer get blind => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get blindedElement => CipherBirdBuffer._(_memory, _base + 8);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 16));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 16, value.address);
}
