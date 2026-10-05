part of '../native_platform.dart';

final class CipherBirdBuffer extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;
}
