part of '../cipher_bird.dart';

DynamicLibrary _openLibrary(String? path) {
  final explicit = (path ?? '').isNotEmpty ? path : null;
  final resolved =
      explicit ??
      Platform.environment['CIPHERBIRD_LIBRARY'] ??
      Platform.environment['CRYPTOLIB_DYLIB'] ??
      _bundledLibraryPath();
  if (resolved != null && resolved.isNotEmpty) {
    return DynamicLibrary.open(resolved);
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('libcryptolib_c.so');
  }
  return DynamicLibrary.process();
}
