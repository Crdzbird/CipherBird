part of '../../cryptolib_ffi.dart';

/// A media file as the key - the same file always yields the same key.
///
/// Uses the DETERMINISTIC entropy path deliberately: `keyFromFile` XORs in
/// fresh system entropy and so could never reopen its own envelope.
final class KeyFileSource extends KeySource with _Builtin {
  const KeyFileSource(this.path);
  final String path;
  @override
  int get id => 2;
  @override
  String get label => 'keyFile';
  @override
  Uint8List deriveRoot(CryptoLib lib, Uint8List salt, int ops, int mem) {
    final handle = lib.entropyFromFileDeterministic(path);
    try {
      return lib.entropySymmetricKey(handle);
    } finally {
      lib.entropyFree(handle);
    }
  }
}
