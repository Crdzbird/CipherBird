part of '../web_platform.dart';

/// Web view of the C `CryptoBufferResult` struct.
final class CipherBirdBufferResult extends Struct {
  const CipherBirdBufferResult._(super.memory, super.base);

  static CipherBirdBufferResult _new(Memory memory, int base) =>
      CipherBirdBufferResult._(memory, base);

  /// Byte size under wasm32.
  static const int size = 12;

  CipherBirdBuffer get buf => CipherBirdBuffer._(_memory, _base + 0);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 8));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 8, value.address);
}
