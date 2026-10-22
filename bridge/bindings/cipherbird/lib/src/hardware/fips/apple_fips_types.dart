import 'dart:ffi';

/// Native signatures of the `@_cdecl` functions in `FipsCrypto.swift`.
typedef OutC = Pointer<Pointer<Uint8>>;
typedef LenC = Pointer<IntPtr>;
typedef ModuleC = Int32 Function(OutC, LenC);
typedef ModuleD = int Function(OutC, LenC);
typedef DigestC = Int32 Function(Int32, Pointer<Uint8>, IntPtr, OutC, LenC);
typedef DigestD = int Function(int, Pointer<Uint8>, int, OutC, LenC);
typedef HmacC =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      OutC,
      LenC,
    );
typedef HmacD =
    int Function(int, Pointer<Uint8>, int, Pointer<Uint8>, int, OutC, LenC);
typedef HkdfC =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      IntPtr,
      OutC,
      LenC,
    );
typedef HkdfD =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      int,
      OutC,
      LenC,
    );
typedef Pbkdf2C =
    Int32 Function(
      Int32,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Uint32,
      IntPtr,
      OutC,
      LenC,
    );
typedef Pbkdf2D =
    int Function(
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      int,
      int,
      OutC,
      LenC,
    );
typedef RandomC = Int32 Function(IntPtr, OutC, LenC);
typedef RandomD = int Function(int, OutC, LenC);
typedef ThreeBufC =
    Int32 Function(
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      Pointer<Uint8>,
      IntPtr,
      OutC,
      LenC,
    );
typedef ThreeBufD =
    int Function(
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      Pointer<Uint8>,
      int,
      OutC,
      LenC,
    );
