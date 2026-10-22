part of '../native_platform.dart';

final class CipherBirdFipsStatus extends Struct {
  @Int32()
  external int loaded;
  @Int32()
  external int selfTestsPassed;
  @Int32()
  external int approvedMode;
  external Pointer<Utf8> providerName;
  external Pointer<Utf8> providerVersion;
  external Pointer<Utf8> moduleDirectory;
  external Pointer<Utf8> configFile;
}
