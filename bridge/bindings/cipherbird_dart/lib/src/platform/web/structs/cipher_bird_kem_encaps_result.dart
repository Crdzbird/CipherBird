part of '../web_platform.dart';

/// Web view of the C `CryptoKemEncapsResult` struct.
final class CipherBirdKemEncapsResult extends Struct {
  const CipherBirdKemEncapsResult._(super.memory, super.base);

  static CipherBirdKemEncapsResult _new(Memory memory, int base) =>
      CipherBirdKemEncapsResult._(memory, base);

  /// Byte size under wasm32.
  static const int size = 16;

  CipherBirdBuffer get ciphertext => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get sharedSecret => CipherBirdBuffer._(_memory, _base + 8);
}
