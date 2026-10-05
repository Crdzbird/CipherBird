part of 'native_platform.dart';

/// Opens the native engine: an explicit [path], else the `CIPHERBIRD_LIBRARY`
/// or `CRYPTOLIB_DYLIB` environment variable, else the bundled library.
DynamicLibrary openEngineLibrary(String? path) {
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
    return DynamicLibrary.open('libcipherbird.so');
  }
  return DynamicLibrary.process();
}

/// Nothing to prepare on native platforms: the library opens synchronously.
Future<void> prepareEngine(String? library) async {}
