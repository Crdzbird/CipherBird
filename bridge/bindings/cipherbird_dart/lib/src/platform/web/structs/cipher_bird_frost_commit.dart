part of '../web_platform.dart';

/// Web view of the C `CryptoFrostCommit` struct.
final class CipherBirdFrostCommit extends Struct {
  const CipherBirdFrostCommit._(super.memory, super.base);

  static CipherBirdFrostCommit _new(Memory memory, int base) =>
      CipherBirdFrostCommit._(memory, base);

  /// Byte size under wasm32.
  static const int size = 36;

  CipherBirdBuffer get hidingNonce => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get bindingNonce => CipherBirdBuffer._(_memory, _base + 8);
  CipherBirdBuffer get hidingCommit => CipherBirdBuffer._(_memory, _base + 16);
  CipherBirdBuffer get bindingCommit => CipherBirdBuffer._(_memory, _base + 24);
  Pointer<Utf8> get error => Pointer<Utf8>._(_memory.getU32(_base + 32));
  set error(Pointer<Utf8> value) => _memory.setU32(_base + 32, value.address);
}
