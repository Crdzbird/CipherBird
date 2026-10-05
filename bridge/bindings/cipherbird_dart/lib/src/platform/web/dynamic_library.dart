part of 'web_platform.dart';

/// Resolves C ABI symbol names to Dart closures over the WebAssembly engine,
/// with the shape of dart:ffi's `DynamicLibrary.lookupFunction`.
final class DynamicLibrary {
  DynamicLibrary._();

  /// Looks up [symbol]; [D] must be the Dart signature the native build uses.
  D lookupFunction<C extends Function, D extends Function>(String symbol) {
    final function = symbolRegistry[symbol];
    if (function == null) {
      throw ArgumentError('cipherbird: unknown engine symbol $symbol');
    }
    return function as D;
  }
}

/// Returns the loaded engine as a [DynamicLibrary]. On the web [path] is
/// accepted for API symmetry only; the engine URL is chosen by
/// [prepareEngine].
DynamicLibrary openEngineLibrary(String? path) {
  WebEngine.current;
  return DynamicLibrary._();
}
