import 'dart:ffi';

import 'package:ffi/ffi.dart';

typedef _CreateC = Int32 Function(Pointer<Utf8>, Int32);
typedef _LabelC = Int32 Function(Pointer<Utf8>);
typedef _OutC =
    Int32 Function(
      Pointer<Utf8>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _WrapC =
    Int32 Function(
      Pointer<Utf8>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _UnwrapC =
    Int32 Function(
      Pointer<Utf8>,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Utf8>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
typedef _FreeC = Void Function(Pointer<Uint8>, IntPtr);
typedef _LastErrorC = Int32 Function(Pointer<Pointer<Uint8>>, Pointer<IntPtr>);

/// The last platform error description.
typedef LastErrorFn = int Function(Pointer<Pointer<Uint8>>, Pointer<IntPtr>);

/// The `@_cdecl` functions of `HardwareKey.swift`, resolved once.
final class AppleBindings {
  AppleBindings._(DynamicLibrary lib)
    : create = lib.lookupFunction<_CreateC, int Function(Pointer<Utf8>, int)>(
        'cipherbird_hw_create',
      ),
      exists = lib.lookupFunction<_LabelC, int Function(Pointer<Utf8>)>(
        'cipherbird_hw_exists',
      ),
      delete = lib.lookupFunction<_LabelC, int Function(Pointer<Utf8>)>(
        'cipherbird_hw_delete',
      ),
      backing = lib.lookupFunction<_LabelC, int Function(Pointer<Utf8>)>(
        'cipherbird_hw_backing',
      ),
      publicKey = lib.lookupFunction<_OutC, OutFn>('cipherbird_hw_public_key'),
      wrap = lib.lookupFunction<_WrapC, WrapFn>('cipherbird_hw_wrap'),
      unwrap = lib.lookupFunction<_UnwrapC, UnwrapFn>('cipherbird_hw_unwrap'),
      attest = lib.lookupFunction<_WrapC, WrapFn>('cipherbird_hw_attest'),
      lastError = lib.lookupFunction<_LastErrorC, LastErrorFn>(
        'cipherbird_hw_last_error',
      ),
      free = lib.lookupFunction<_FreeC, void Function(Pointer<Uint8>, int)>(
        'cipherbird_hw_free',
      );

  /// Resolves the symbols from the running process.
  factory AppleBindings.process() => AppleBindings._(DynamicLibrary.process());

  final int Function(Pointer<Utf8>, int) create;
  final int Function(Pointer<Utf8>) exists;
  final int Function(Pointer<Utf8>) delete;
  final int Function(Pointer<Utf8>) backing;
  final OutFn publicKey;
  final WrapFn wrap;
  final UnwrapFn unwrap;
  final WrapFn attest;
  final LastErrorFn lastError;
  final void Function(Pointer<Uint8>, int) free;
}

typedef OutFn =
    int Function(Pointer<Utf8>, Pointer<Pointer<Uint8>>, Pointer<IntPtr>);

typedef WrapFn =
    int Function(
      Pointer<Utf8>,
      Pointer<Uint8>,
      int,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );

/// Unwrap: input, a prompt reason, and one output buffer.
typedef UnwrapFn =
    int Function(
      Pointer<Utf8>,
      Pointer<Uint8>,
      int,
      Pointer<Utf8>,
      Pointer<Pointer<Uint8>>,
      Pointer<IntPtr>,
    );
