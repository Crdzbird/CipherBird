part of '../native_platform.dart';

final class CipherBirdFrostCommit extends Struct {
  external CipherBirdBuffer hidingNonce;
  external CipherBirdBuffer bindingNonce;
  external CipherBirdBuffer hidingCommit;
  external CipherBirdBuffer bindingCommit;
  external Pointer<Utf8> error;
}
