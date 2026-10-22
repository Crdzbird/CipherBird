part of '../web_platform.dart';

/// Web view of the C `CryptoHealthReport2` struct.
final class CipherBirdHealthReport2 extends Struct {
  const CipherBirdHealthReport2._(super.memory, super.base);

  static CipherBirdHealthReport2 _new(Memory memory, int base) =>
      CipherBirdHealthReport2._(memory, base);

  /// Byte size under wasm32.
  static const int size = 96;

  double get minEntropyPerByte => _memory.getF64(_base + 0);
  double get mcvBitsPerByte => _memory.getF64(_base + 8);
  double get markovBitsPerByte => _memory.getF64(_base + 16);
  double get floorBitsPerByte => _memory.getF64(_base + 24);
  int get sampleBytes => _memory.getU64(_base + 32);
  set sampleBytes(int value) => _memory.setU64(_base + 32, value);
  int get longestRun => _memory.getU64(_base + 40);
  set longestRun(int value) => _memory.setU64(_base + 40, value);
  int get rctCutoff => _memory.getU64(_base + 48);
  set rctCutoff(int value) => _memory.setU64(_base + 48, value);
  int get maxWindowCount => _memory.getU64(_base + 56);
  set maxWindowCount(int value) => _memory.setU64(_base + 56, value);
  int get aptCutoff => _memory.getU64(_base + 64);
  set aptCutoff(int value) => _memory.setU64(_base + 64, value);
  int get aptWindow => _memory.getU64(_base + 72);
  set aptWindow(int value) => _memory.setU64(_base + 72, value);
  int get rctPassed => _memory.getI32(_base + 80);
  set rctPassed(int value) => _memory.setI32(_base + 80, value);
  int get aptPassed => _memory.getI32(_base + 84);
  set aptPassed(int value) => _memory.setI32(_base + 84, value);
  Pointer<Utf8> get summary => Pointer<Utf8>._(_memory.getU32(_base + 88));
  set summary(Pointer<Utf8> value) => _memory.setU32(_base + 88, value.address);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 92));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 92, value.address);
}
