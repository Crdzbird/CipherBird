part of '../native_platform.dart';

final class CipherBirdOpaqueRecord extends Struct {
  external CipherBirdBuffer record;
  external CipherBirdBuffer exportKey;
  external Pointer<Utf8> error;
}
