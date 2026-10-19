part of 'native_platform.dart';

/// Allocates native memory the way `package:ffi` does and overwrites every
/// block with zeros before it is freed, so the copies of keys, passwords and
/// plaintext that cross the FFI boundary never outlive their call.
final class ZeroingAllocator implements Allocator {
  const ZeroingAllocator._(this._inner);

  final Allocator _inner;

  static final Map<int, int> _sizes = {};

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    final pointer = _inner.allocate<T>(byteCount, alignment: alignment);
    _sizes[pointer.address] = byteCount;
    return pointer;
  }

  @override
  void free(Pointer<NativeType> pointer) {
    final size = _sizes.remove(pointer.address);
    if (size != null && size > 0) {
      pointer.cast<Uint8>().asTypedList(size).fillRange(0, size, 0);
    }
    _inner.free(pointer);
  }
}

/// Zero-filling allocator; every block is wiped again on free.
const ZeroingAllocator calloc = ZeroingAllocator._(ffi.calloc);

/// Plain allocator; every block is wiped on free.
const ZeroingAllocator malloc = ZeroingAllocator._(ffi.malloc);
