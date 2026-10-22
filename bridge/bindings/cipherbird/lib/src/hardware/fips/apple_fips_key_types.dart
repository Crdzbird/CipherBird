import 'dart:ffi';

import 'package:cipherbird/src/hardware/fips/apple_fips_types.dart';

/// Native signatures of the P-256 functions in `FipsCrypto.swift`.
typedef KeygenC = Int32 Function(OutC, LenC, OutC, LenC);
typedef KeygenD = int Function(OutC, LenC, OutC, LenC);
typedef TwoBufC =
    Int32 Function(Pointer<Uint8>, IntPtr, Pointer<Uint8>, IntPtr, OutC, LenC);
typedef TwoBufD =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, OutC, LenC);
typedef VerifyC =
    Int32 Function(
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
    );
typedef VerifyD =
    int Function(Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
typedef OneBufC = Int32 Function(Pointer<Uint8>, IntPtr, OutC, LenC);
typedef OneBufD = int Function(Pointer<Uint8>, int, OutC, LenC);
typedef FreeC = Void Function(Pointer<Uint8>, IntPtr);
typedef FreeD = void Function(Pointer<Uint8>, int);
