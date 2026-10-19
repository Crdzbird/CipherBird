part of 'native_platform.dart';

/// UTF-8 encoding into native memory that is wiped on free. Replaces the
/// `package:ffi` extension of the same name, whose allocation is not wiped.
extension ZeroingStringUtf8 on String {
  Pointer<Utf8> toNativeUtf8({Allocator allocator = malloc}) {
    final encoded = utf8.encode(this);
    final out = allocator<Uint8>(encoded.length + 1);
    out.asTypedList(encoded.length + 1)
      ..setAll(0, encoded)
      ..[encoded.length] = 0;
    encoded.fillRange(0, encoded.length, 0);
    return out.cast<Utf8>();
  }
}
