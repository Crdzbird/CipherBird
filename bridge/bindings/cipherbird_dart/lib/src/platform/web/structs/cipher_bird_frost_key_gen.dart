part of '../web_platform.dart';

/// Web view of the C `CryptoFrostKeyGen` struct.
final class CipherBirdFrostKeyGen extends Struct {
  const CipherBirdFrostKeyGen._(super.memory, super.base);

  static CipherBirdFrostKeyGen _new(Memory memory, int base) =>
      CipherBirdFrostKeyGen._(memory, base);

  /// Byte size under wasm32.
  static const int size = 32;

  CipherBirdBuffer get groupPublicKey => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get secretShares => CipherBirdBuffer._(_memory, _base + 8);
  CipherBirdBuffer get publicShares => CipherBirdBuffer._(_memory, _base + 16);
  int get count => _memory.getU32(_base + 24);
  set count(int value) => _memory.setU32(_base + 24, value);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 28));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 28, value.address);
}
