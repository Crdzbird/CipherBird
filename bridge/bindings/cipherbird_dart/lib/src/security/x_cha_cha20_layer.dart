part of '../cryptolib.dart';

/// XChaCha20-Poly1305 layer.
final class XChaCha20Layer extends ProtectionLayer with _Builtin {
  const XChaCha20Layer();
  @override
  int get id => 1;
  @override
  String get wireName => 'xchacha20Poly1305';
  @override
  Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) =>
      lib.xchacha20Encrypt(pt, key, aad);
  @override
  Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) =>
      lib.xchacha20Decrypt(ct, key, aad);
}
