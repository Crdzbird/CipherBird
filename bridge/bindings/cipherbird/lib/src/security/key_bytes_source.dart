part of '../cipher_bird.dart';

/// A media buffer as the key - the same bytes always yield the same key.
///
/// The in-memory counterpart of [KeyFileSource], for a photo picked in a
/// browser or held in memory; uses the deterministic entropy path for the
/// same reason.
final class KeyBytesSource extends KeySource with _Builtin {
  KeyBytesSource(Uint8List bytes) : _bytes = Uint8List.fromList(bytes);
  final Uint8List _bytes;
  @override
  int get id => 3;
  @override
  String get label => 'keyBytes';
  @override
  Uint8List deriveRoot(CipherBird lib, Uint8List salt, int ops, int mem) {
    final handle = lib.entropyFromBytes(_bytes, deterministic: true);
    try {
      return lib.entropySymmetricKey(handle);
    } finally {
      lib.entropyFree(handle);
    }
  }
}
