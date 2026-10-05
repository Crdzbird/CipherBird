part of '../native_platform.dart';

final class CipherBirdOpaqueKe3 extends Struct {
  external CipherBirdBuffer ke3;
  external CipherBirdBuffer sessionKey;
  external CipherBirdBuffer exportKey;
  external Pointer<Utf8> error;
}
