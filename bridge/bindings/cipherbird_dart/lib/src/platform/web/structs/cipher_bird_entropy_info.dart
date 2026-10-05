part of '../web_platform.dart';

/// Web view of the C `CryptoEntropyInfo` struct.
final class CipherBirdEntropyInfo extends Struct {
  const CipherBirdEntropyInfo._(super.memory, super.base);

  static CipherBirdEntropyInfo _new(Memory memory, int base) =>
      CipherBirdEntropyInfo._(memory, base);

  /// Byte size under wasm32.
  static const int size = 32;

  Pointer<Utf8> get path => Pointer<Utf8>._(_memory.getU32(_base + 0));
  set path(Pointer<Utf8> value) => _memory.setU32(_base + 0, value.address);
  int get fileSize => _memory.getU64(_base + 8);
  set fileSize(int value) => _memory.setU64(_base + 8, value);
  int get chunksRead => _memory.getU64(_base + 16);
  set chunksRead(int value) => _memory.setU64(_base + 16, value);
  double get entropyBits => _memory.getF64(_base + 24);
}
