part of '../native_platform.dart';

/// What one feed of a live entropy source did (`cryptolib_live_entropy_feed`).
final class CipherBirdLiveFeedReport extends Struct {
  @Int32()
  external int accepted;

  @Double()
  external double creditedBits;

  @Double()
  external double creditedBitsTotal;

  @Int32()
  external int ready;

  @Double()
  external double minEntropyPerByte;

  @Uint64()
  external int longestRun;

  @Uint64()
  external int rctCutoff;

  @Int32()
  external int rctPassed;

  @Int32()
  external int aptPassed;

  external Pointer<Utf8> reason;
  external Pointer<Utf8> error;
}
