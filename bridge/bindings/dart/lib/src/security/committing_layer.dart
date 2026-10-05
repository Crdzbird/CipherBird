part of '../../cryptolib_ffi.dart';

/// Key-committing AEAD (UtC) layer.
final class CommittingLayer extends ProtectionLayer with _Builtin {
  const CommittingLayer();
  @override
  int get id => 3;
  @override
  String get wireName => 'committing';
  @override
  Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) =>
      lib.committingEncrypt(pt, key, aad);
  @override
  Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) =>
      lib.committingDecrypt(ct, key, aad);
}
