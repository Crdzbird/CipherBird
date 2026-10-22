part of '../web_platform.dart';

/// Web view of the C `CryptoLiveStatus` struct.
final class CipherBirdLiveStatus extends Struct {
  const CipherBirdLiveStatus._(super.memory, super.base);

  static CipherBirdLiveStatus _new(Memory memory, int base) =>
      CipherBirdLiveStatus._(memory, base);

  /// Byte size under wasm32.
  static const int size = 104;

  int get chunksFed => _memory.getU64(_base + 0);
  set chunksFed(int value) => _memory.setU64(_base + 0, value);
  int get chunksAccepted => _memory.getU64(_base + 8);
  set chunksAccepted(int value) => _memory.setU64(_base + 8, value);
  int get chunksRejected => _memory.getU64(_base + 16);
  set chunksRejected(int value) => _memory.setU64(_base + 16, value);
  int get bytesFed => _memory.getU64(_base + 24);
  set bytesFed(int value) => _memory.setU64(_base + 24, value);
  int get reseeds => _memory.getU64(_base + 32);
  set reseeds(int value) => _memory.setU64(_base + 32, value);
  double get creditedBitsTotal => _memory.getF64(_base + 40);
  double get creditedBitsSinceReseed => _memory.getF64(_base + 48);
  double get minCreditedBits => _memory.getF64(_base + 56);
  int get ready => _memory.getI32(_base + 64);
  set ready(int value) => _memory.setI32(_base + 64, value);
  double get lastMinEntropyPerByte => _memory.getF64(_base + 72);
  int get lastLongestRun => _memory.getU64(_base + 80);
  set lastLongestRun(int value) => _memory.setU64(_base + 80, value);
  int get lastRctCutoff => _memory.getU64(_base + 88);
  set lastRctCutoff(int value) => _memory.setU64(_base + 88, value);
  Pointer<Utf8> get lastReason => Pointer<Utf8>._(_memory.getU32(_base + 96));
  set lastReason(Pointer<Utf8> value) =>
      _memory.setU32(_base + 96, value.address);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 100));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 100, value.address);
}
