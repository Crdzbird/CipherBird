import 'dart:ffi';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/apple_fips_bindings.dart';
import 'package:cipherbird/src/hardware/fips/fips_exception.dart';
import 'package:ffi/ffi.dart';

/// Marshalling for the Swift validated-module calls: inputs as wiped native
/// copies, outputs copied out and released through the Swift side, status
/// codes turned into [FipsException].
final class AppleFipsCall {
  const AppleFipsCall._();

  static AppleFipsBindings? _bindings;

  static AppleFipsBindings get bindings =>
      _bindings ??= AppleFipsBindings.process();

  static const Map<int, String> _codes = {
    -1: 'unsupported',
    -4: 'authentication_failed',
    -5: 'failed',
    -6: 'bad_argument',
  };

  /// Throws for a non-zero [status].
  static void check(int status) {
    if (status == 0) {
      return;
    }
    throw FipsException(_codes[status] ?? 'failed', 'platform status $status');
  }

  /// Runs [call] with native copies of [inputs] and one output buffer.
  static Uint8List run(
    List<Uint8List> inputs,
    int Function(
      AppleFipsBindings b,
      List<Pointer<Uint8>> ins,
      Pointer<Pointer<Uint8>> out,
      Pointer<IntPtr> len,
    )
    call,
  ) {
    final ins = [for (final i in inputs) toNative(i)];
    final out = calloc<Pointer<Uint8>>();
    final len = calloc<IntPtr>();
    try {
      check(call(bindings, ins, out, len));
      return take(out, len);
    } finally {
      for (var i = 0; i < ins.length; i++) {
        freeNative(ins[i], inputs[i].length);
      }
      calloc.free(out);
      calloc.free(len);
    }
  }

  /// Copies the buffer the Swift side filled and releases it there.
  static Uint8List take(Pointer<Pointer<Uint8>> out, Pointer<IntPtr> len) {
    final copy = Uint8List.fromList(out.value.asTypedList(len.value));
    bindings.free(out.value, len.value);
    return copy;
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
