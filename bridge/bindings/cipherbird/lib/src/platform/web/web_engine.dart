part of 'web_platform.dart';

/// The loaded WebAssembly engine: one per page, created by [prepareEngine].
final class WebEngine {
  WebEngine._(this.module, this.base) : memory = HeapMemory(module);

  /// The Emscripten module.
  final EngineModule module;

  /// Absolute URL of the directory the engine was loaded from.
  final String base;

  /// Live heap access.
  final HeapMemory memory;

  static WebEngine? _current;

  /// The engine, or a clear error when it was never loaded.
  static WebEngine get current {
    final engine = _current;
    if (engine == null) {
      throw StateError(
        'cipherbird: the WebAssembly engine is not loaded; '
        'await CipherBird.preload() before the first use on the web',
      );
    }
    return engine;
  }

  /// Whether [prepareEngine] completed.
  static bool get isLoaded => _current != null;

  int malloc(int bytes) => module.malloc(bytes);

  void free(int address) => module.free(address);

  /// Calls an exported wrapper and returns its 32-bit result.
  int callInt(String export, List<JSAny?> args) {
    final result = module.callMethodVarArgs<JSAny?>(export.toJS, args);
    if (result == null) {
      return 0;
    }
    return (result as JSNumber).toDartInt;
  }

  /// Calls an exported wrapper that returns nothing.
  void callVoid(String export, List<JSAny?> args) {
    module.callMethodVarArgs<JSAny?>(export.toJS, args);
  }

  /// Calls a wrapper that writes a struct of [size] bytes to its first
  /// argument and returns a detached copy of that struct.
  T callStruct<T extends Struct>(
    String export,
    List<JSAny?> args,
    int size,
    T Function(Memory memory, int base) make,
  ) {
    final out = malloc(size);
    try {
      callVoid(export, [out.toJS, ...args]);
      return make(LocalMemory.copyFrom(memory, out, size), 0);
    } finally {
      free(out);
    }
  }

  /// Calls a wrapper that writes a 64-bit integer as two halves.
  int callU64(String export, List<JSAny?> args) {
    final out = malloc(8);
    try {
      callVoid(export, [out.toJS, ...args]);
      return memory.getU64(out);
    } finally {
      free(out);
    }
  }
}
