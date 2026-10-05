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
}
