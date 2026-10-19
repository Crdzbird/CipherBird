import 'dart:ffi';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/apple_bindings.dart';
import 'package:cipherbird/src/hardware/apple_last_error.dart';
import 'package:cipherbird/src/hardware/hardware_key_exception.dart';
import 'package:ffi/ffi.dart';

/// Marshalling for the Swift hardware-key calls: labels as C strings,
/// inputs as wiped native copies, outputs copied out and freed through the
/// Swift side, status codes turned into [HardwareKeyException].
final class AppleCall {
  const AppleCall._();

  static AppleBindings? _bindings;

  static AppleBindings get bindings => _bindings ??= AppleBindings.process();

  static const Map<int, String> _codes = {
    -1: 'unsupported',
    -2: 'not_found',
    -3: 'exists',
    -4: 'authentication_failed',
    -5: 'failed',
    -6: 'bad_argument',
  };

  /// Throws for a non-zero [status].
  static void check(int status) {
    if (status == 0) {
      return;
    }
    final code = _codes[status] ?? 'failed';
    throw HardwareKeyException(
      code,
      'platform status $status: ${appleLastError(bindings)}',
    );
  }

  /// Runs [call] with [label] as a C string.
  static int withLabel(
    String label,
    int Function(AppleBindings b, Pointer<Utf8> label) call,
  ) {
    final plabel = label.toNativeUtf8();
    try {
      return call(bindings, plabel);
    } finally {
      malloc.free(plabel);
    }
  }

  /// Runs [call], which fills an output buffer, and returns a copy of it.
  static Uint8List withOutput(
    String label,
    int Function(
      AppleBindings b,
      Pointer<Utf8> label,
      Pointer<Pointer<Uint8>> out,
      Pointer<IntPtr> len,
    )
    call,
  ) {
    final out = calloc<Pointer<Uint8>>();
    final len = calloc<IntPtr>();
    try {
      check(withLabel(label, (b, l) => call(b, l, out, len)));
      final copy = Uint8List.fromList(out.value.asTypedList(len.value));
      bindings.free(out.value, len.value);
      return copy;
    } finally {
      calloc.free(out);
      calloc.free(len);
    }
  }

  /// A native copy of [bytes]; release with [freeNative].
  static Pointer<Uint8> toNative(Uint8List bytes) {
    final p = malloc<Uint8>(bytes.isEmpty ? 1 : bytes.length);
    p.asTypedList(bytes.length).setAll(0, bytes);
    return p;
  }

  /// Wipes and frees a copy made by [toNative].
  static void freeNative(Pointer<Uint8> p, int length) {
    p.asTypedList(length).fillRange(0, length, 0);
    malloc.free(p);
  }
}
