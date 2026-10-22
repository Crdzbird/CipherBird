part of '../web_platform.dart';

/// Web view of the C `CryptoFipsStatus` struct.
final class CipherBirdFipsStatus extends Struct {
  const CipherBirdFipsStatus._(super.memory, super.base);

  static CipherBirdFipsStatus _new(Memory memory, int base) =>
      CipherBirdFipsStatus._(memory, base);

  /// Byte size under wasm32.
  static const int size = 28;

  int get loaded => _memory.getI32(_base + 0);
  set loaded(int value) => _memory.setI32(_base + 0, value);
  int get selfTestsPassed => _memory.getI32(_base + 4);
  set selfTestsPassed(int value) => _memory.setI32(_base + 4, value);
  int get approvedMode => _memory.getI32(_base + 8);
  set approvedMode(int value) => _memory.setI32(_base + 8, value);
  Pointer<Utf8> get providerName => Pointer<Utf8>._(_memory.getU32(_base + 12));
  set providerName(Pointer<Utf8> value) =>
      _memory.setU32(_base + 12, value.address);
  Pointer<Utf8> get providerVersion =>
      Pointer<Utf8>._(_memory.getU32(_base + 16));
  set providerVersion(Pointer<Utf8> value) =>
      _memory.setU32(_base + 16, value.address);
  Pointer<Utf8> get moduleDirectory =>
      Pointer<Utf8>._(_memory.getU32(_base + 20));
  set moduleDirectory(Pointer<Utf8> value) =>
      _memory.setU32(_base + 20, value.address);
  Pointer<Utf8> get configFile => Pointer<Utf8>._(_memory.getU32(_base + 24));
  set configFile(Pointer<Utf8> value) =>
      _memory.setU32(_base + 24, value.address);
}
