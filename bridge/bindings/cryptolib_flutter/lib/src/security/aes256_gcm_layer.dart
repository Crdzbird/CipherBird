part of '../cryptolib.dart';

/// AES-256-GCM layer.
final class Aes256GcmLayer extends ProtectionLayer with _Builtin {
  const Aes256GcmLayer();
  @override
  int get id => 2;
  @override
  String get wireName => 'aes256Gcm';
  @override
  Uint8List seal(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List pt) =>
      lib.aes256gcmEncrypt(pt, key, aad);
  @override
  Uint8List open(CryptoLib lib, Uint8List key, Uint8List aad, Uint8List ct) =>
      lib.aes256gcmDecrypt(ct, key, aad);
}
