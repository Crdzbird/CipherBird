part of '../native_platform.dart';

final class CipherBirdPacket extends Struct {
  external CipherBirdBuffer ciphertext;
  external CipherBirdBuffer signature;
  external CipherBirdBuffer kdfSalt;
}
