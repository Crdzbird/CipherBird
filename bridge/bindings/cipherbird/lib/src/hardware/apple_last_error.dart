import 'dart:ffi';

import 'package:cipherbird/src/hardware/apple_bindings.dart';
import 'package:ffi/ffi.dart';

/// The description of the last platform failure, for exception messages.
String appleLastError(AppleBindings bindings) {
  final out = calloc<Pointer<Uint8>>();
  final len = calloc<IntPtr>();
  try {
    if (bindings.lastError(out, len) != 0) {
      return '';
    }
    final text = String.fromCharCodes(out.value.asTypedList(len.value));
    bindings.free(out.value, len.value);
    return text;
  } finally {
    calloc.free(out);
    calloc.free(len);
  }
}
