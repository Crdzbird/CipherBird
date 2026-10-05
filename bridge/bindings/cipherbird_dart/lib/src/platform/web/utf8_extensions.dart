part of 'web_platform.dart';

/// UTF-8 decoding of a C string.
extension Utf8Pointer on Pointer<Utf8> {
  int get length {
    var n = 0;
    while (_heap.getU8(address + n) != 0) {
      n++;
    }
    return n;
  }

  String toDartString({int? length}) =>
      utf8.decode(_heap.view(address, length ?? this.length));
}

/// UTF-8 encoding into a fresh heap allocation.
extension StringUtf8Pointer on String {
  Pointer<Utf8> toNativeUtf8({WebAllocator allocator = malloc}) {
    final encoded = utf8.encode(this);
    final out = allocator<Uint8>(encoded.length + 1);
    out.asTypedList(encoded.length + 1)
      ..setAll(0, encoded)
      ..[encoded.length] = 0;
    return out.cast<Utf8>();
  }
}
