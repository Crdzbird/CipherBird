part of 'web_platform.dart';

/// Allocates in the engine's heap through its exported `malloc` and `free`,
/// with the call shape of dart:ffi's `calloc` and `malloc`.
final class WebAllocator {
  const WebAllocator._(this._zeroed);

  final bool _zeroed;

  /// Allocates [count] elements of [T]; zero-filled for `calloc`.
  Pointer<T> call<T extends NativeType>([int count = 1]) {
    final bytes = sizeOf<T>() * count;
    final engine = WebEngine.current;
    final address = engine.malloc(bytes == 0 ? 1 : bytes);
    if (address == 0) {
      throw StateError('cipherbird: WebAssembly memory exhausted');
    }
    if (_zeroed && bytes > 0) {
      engine.memory.view(address, bytes).fillRange(0, bytes, 0);
    }
    return Pointer<T>._(address);
  }

  /// Releases [pointer]; the null pointer is ignored.
  void free(Pointer<NativeType> pointer) {
    if (pointer.address != 0) {
      WebEngine.current.free(pointer.address);
    }
  }
}

/// Zero-filling allocator.
const WebAllocator calloc = WebAllocator._(true);

/// Plain allocator.
const WebAllocator malloc = WebAllocator._(false);
