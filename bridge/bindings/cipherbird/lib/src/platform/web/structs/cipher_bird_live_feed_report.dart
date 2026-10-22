part of '../web_platform.dart';

/// Web view of the C `CryptoLiveFeedReport` struct.
final class CipherBirdLiveFeedReport extends Struct {
  const CipherBirdLiveFeedReport._(super.memory, super.base);

  static CipherBirdLiveFeedReport _new(Memory memory, int base) =>
      CipherBirdLiveFeedReport._(memory, base);

  /// Byte size under wasm32.
  static const int size = 72;

  int get accepted => _memory.getI32(_base + 0);
  set accepted(int value) => _memory.setI32(_base + 0, value);
  double get creditedBits => _memory.getF64(_base + 8);
  double get creditedBitsTotal => _memory.getF64(_base + 16);
  int get ready => _memory.getI32(_base + 24);
  set ready(int value) => _memory.setI32(_base + 24, value);
  double get minEntropyPerByte => _memory.getF64(_base + 32);
  int get longestRun => _memory.getU64(_base + 40);
  set longestRun(int value) => _memory.setU64(_base + 40, value);
  int get rctCutoff => _memory.getU64(_base + 48);
  set rctCutoff(int value) => _memory.setU64(_base + 48, value);
  int get rctPassed => _memory.getI32(_base + 56);
  set rctPassed(int value) => _memory.setI32(_base + 56, value);
  int get aptPassed => _memory.getI32(_base + 60);
  set aptPassed(int value) => _memory.setI32(_base + 60, value);
  Pointer<Utf8> get reason => Pointer<Utf8>._(_memory.getU32(_base + 64));
  set reason(Pointer<Utf8> value) => _memory.setU32(_base + 64, value.address);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 68));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 68, value.address);
}
