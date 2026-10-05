part of '../native_platform.dart';

final class CipherBirdFrostKeyGen extends Struct {
  external CipherBirdBuffer groupPublicKey;
  external CipherBirdBuffer secretShares;
  external CipherBirdBuffer publicShares;

  @Size()
  external int count;
  external Pointer<Utf8> error;
}
