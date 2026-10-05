part of '../../cipher_bird.dart';

typedef _Argon2idHashStrC =
    CryptoBufferResult Function(Pointer<Utf8> password, Uint64 ops, Size mem);
typedef _Argon2idHashStrDart =
    CryptoBufferResult Function(Pointer<Utf8> password, int ops, int mem);
typedef _Argon2idVerifyStrC =
    Int32 Function(Pointer<Utf8> password, Pointer<Utf8> phcStr);
typedef _Argon2idVerifyStrDart =
    int Function(Pointer<Utf8> password, Pointer<Utf8> phcStr);
typedef _Argon2idDeriveC =
    CryptoBufferResult Function(
      Pointer<Utf8> password,
      Pointer<Uint8> salt,
      Size saltLen,
      Size keyLen,
      Uint64 ops,
      Size mem,
    );
typedef _Argon2idDeriveDart =
    CryptoBufferResult Function(
      Pointer<Utf8> password,
      Pointer<Uint8> salt,
      int saltLen,
      int keyLen,
      int ops,
      int mem,
    );
