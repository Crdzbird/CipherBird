part of '../cryptolib.dart';

/// A 32-byte key used as-is - from a KEM shared secret, a keyring unlock, a
/// token. Nothing is stretched; the key must already be full-entropy.
final class RawKeySource extends KeySource with _Builtin {
  RawKeySource(Uint8List key) : _key = Uint8List.fromList(key) {
    if (key.length != 32) {
      throw ArgumentError.value(
        key.length,
        'key.length',
        'root key must be exactly 32 bytes',
      );
    }
  }
  final Uint8List _key;
  @override
  int get id => 0;
  @override
  String get label => 'raw';
  @override
  Uint8List deriveRoot(CryptoLib lib, Uint8List salt, int ops, int mem) => _key;
}
