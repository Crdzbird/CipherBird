part of '../cryptolib.dart';

/// A whole MolecularVault as one layer.
final class MolecularLayer extends ProtectionLayer with _Builtin {
  const MolecularLayer();
  @override
  int get id => 4;
  @override
  String get wireName => 'molecular';
  @override
  Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) =>
      lib.molecularSealWithKey(pt, key, aad: aad);
  @override
  Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) =>
      lib.molecularOpenWithKey(ct, key, aad: aad);
}
