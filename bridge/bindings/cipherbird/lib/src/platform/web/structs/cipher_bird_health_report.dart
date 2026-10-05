part of '../web_platform.dart';

/// Web view of the C `CryptoHealthReport` struct.
final class CipherBirdHealthReport extends Struct {
  const CipherBirdHealthReport._(super.memory, super.base);

  static CipherBirdHealthReport _new(Memory memory, int base) =>
      CipherBirdHealthReport._(memory, base);

  /// Byte size under wasm32.
  static const int size = 40;

  double get minEntropyPerByte => _memory.getF64(_base + 0);
  int get longestRun => _memory.getU64(_base + 8);
  set longestRun(int value) => _memory.setU64(_base + 8, value);
  int get maxWindowCount => _memory.getU64(_base + 16);
  set maxWindowCount(int value) => _memory.setU64(_base + 16, value);
  int get rctPassed => _memory.getI32(_base + 24);
  set rctPassed(int value) => _memory.setI32(_base + 24, value);
  int get aptPassed => _memory.getI32(_base + 28);
  set aptPassed(int value) => _memory.setI32(_base + 28, value);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 32));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 32, value.address);
}
