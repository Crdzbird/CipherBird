part of 'web_platform.dart';

/// A fixed-length inline byte array inside a struct, indexable like
/// dart:ffi's `Array<Uint8>`.
final class Array<T extends NativeType> {
  const Array._(this._memory, this._base, this.length);

  final Memory _memory;
  final int _base;

  /// Element count.
  final int length;

  /// Reads element [index].
  int operator [](int index) => _memory.getU8(_base + index);

  /// Writes element [index].
  void operator []=(int index, int value) =>
      _memory.setU8(_base + index, value);
}
