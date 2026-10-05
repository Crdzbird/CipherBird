part of 'web_platform.dart';

bool _isPointerType<T>() => <T>[] is List<Pointer<NativeType>>;

/// Size in bytes of [T] under the wasm32 ABI.
int sizeOf<T extends NativeType>() {
  if (_isPointerType<T>()) {
    return 4;
  }
  if (T == Uint8 || T == Utf8) {
    return 1;
  }
  if (T == Uint16) {
    return 2;
  }
  if (T == Int32 || T == Size) {
    return 4;
  }
  if (T == Uint64 || T == Double) {
    return 8;
  }
  final size = structSizes[T];
  if (size == null) {
    throw ArgumentError('cipherbird: unknown native type $T');
  }
  return size;
}
