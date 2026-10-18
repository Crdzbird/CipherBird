part of 'native_platform.dart';

/// Release builds (`dart.vm.product`) ignore the environment and the working
/// directory: only an explicit path, the library shipped beside the program
/// or the process image is opened, so nothing on the host can swap the engine
/// of a shipped program.
const bool _productMode = bool.fromEnvironment('dart.vm.product');

String? _environmentOverride() {
  if (_productMode) {
    return null;
  }
  final env = Platform.environment;
  return env['CIPHERBIRD_LIBRARY'] ?? env['CRYPTOLIB_DYLIB'];
}

/// Opens the native engine: an explicit [path], else (outside release builds)
/// the `CIPHERBIRD_LIBRARY` or `CRYPTOLIB_DYLIB` environment variable, else
/// the bundled library.
DynamicLibrary openEngineLibrary(String? path) {
  final explicit = (path ?? '').isNotEmpty ? path : null;
  final resolved = explicit ?? _environmentOverride() ?? _bundledLibraryPath();
  if (resolved != null && resolved.isNotEmpty) {
    return DynamicLibrary.open(resolved);
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('libcipherbird.so');
  }
  return DynamicLibrary.process();
}

/// The native library opens synchronously, so nothing loads ahead of time.
const bool engineLoadsAsynchronously = false;

/// Nothing to prepare on native platforms: the library opens synchronously.
Future<void> prepareEngine(String? library) async {}
