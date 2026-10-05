part of '../web_platform.dart';

/// Web view of the C `CryptoFileInspection` struct.
final class CipherBirdFileInspection extends Struct {
  const CipherBirdFileInspection._(super.memory, super.base);

  static CipherBirdFileInspection _new(Memory memory, int base) =>
      CipherBirdFileInspection._(memory, base);

  /// Byte size under wasm32.
  static const int size = 48;

  int get parses => _memory.getI32(_base + 0);
  set parses(int value) => _memory.setI32(_base + 0, value);
  int get format => _memory.getU8(_base + 4);
  set format(int value) => _memory.setU8(_base + 4, value);
  int get extMatches => _memory.getI32(_base + 8);
  set extMatches(int value) => _memory.setI32(_base + 8, value);
  int get width => _memory.getU64(_base + 16);
  set width(int value) => _memory.setU64(_base + 16, value);
  int get height => _memory.getU64(_base + 24);
  set height(int value) => _memory.setU64(_base + 24, value);
  int get fileSize => _memory.getU64(_base + 32);
  set fileSize(int value) => _memory.setU64(_base + 32, value);
  Pointer<Utf8> get detail => Pointer<Utf8>._(_memory.getU32(_base + 40));
  set detail(Pointer<Utf8> value) => _memory.setU32(_base + 40, value.address);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 44));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 44, value.address);
}
