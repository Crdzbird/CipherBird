part of 'web_platform.dart';

/// The Emscripten module object: linear memory plus the exported allocator.
/// Wrapper functions are reached by name through [WebEngine].
extension type EngineModule._(JSObject _) implements JSObject {
  @JS('HEAPU8')
  external JSUint8Array get heap;

  @JS('_malloc')
  external int malloc(int bytes);

  @JS('_free')
  external void free(int address);

  /// Emscripten's in-memory file system, for the media entry points.
  @JS('FS')
  external EmscriptenFs get fs;
}

/// The subset of Emscripten's `FS` the media scratch uses.
extension type EmscriptenFs._(JSObject _) implements JSObject {
  external void mkdir(String path);
  external void writeFile(String path, JSUint8Array data);
  external JSUint8Array readFile(String path);
  external void unlink(String path);
  external JSObject analyzePath(String path);
}
