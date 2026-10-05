part of '../web_platform.dart';

/// Web view of the C `CryptoHiddenDataReport` struct.
final class CipherBirdHiddenDataReport extends Struct {
  const CipherBirdHiddenDataReport._(super.memory, super.base);

  static CipherBirdHiddenDataReport _new(Memory memory, int base) =>
      CipherBirdHiddenDataReport._(memory, base);

  /// Byte size under wasm32.
  static const int size = 40;

  int get cipherbirdPayload => _memory.getI32(_base + 0);
  set cipherbirdPayload(int value) => _memory.setI32(_base + 0, value);
  double get lsbChiSquare => _memory.getF64(_base + 8);
  double get lsbEmbeddingLikelihood => _memory.getF64(_base + 16);
  int get samplesAnalysed => _memory.getU64(_base + 24);
  set samplesAnalysed(int value) => _memory.setU64(_base + 24, value);
  Pointer<Utf8> get note => Pointer<Utf8>._(_memory.getU32(_base + 32));
  set note(Pointer<Utf8> value) => _memory.setU32(_base + 32, value.address);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 36));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 36, value.address);
}
