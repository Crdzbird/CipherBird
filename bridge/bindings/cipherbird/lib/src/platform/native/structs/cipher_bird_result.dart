part of '../native_platform.dart';

final class CipherBirdResult extends Struct {
  @Int32()
  external int ok;
  external Pointer<Utf8> error;
}
