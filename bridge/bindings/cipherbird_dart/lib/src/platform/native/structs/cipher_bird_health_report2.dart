part of '../native_platform.dart';

/// The full SP 800-90B verdict with every number behind it
/// (`cryptolib_entropy_assess_file_health_v2`).
final class CipherBirdHealthReport2 extends Struct {
  @Double()
  external double minEntropyPerByte;

  @Double()
  external double mcvBitsPerByte;

  @Double()
  external double markovBitsPerByte;

  @Double()
  external double floorBitsPerByte;

  @Uint64()
  external int sampleBytes;

  @Uint64()
  external int longestRun;

  @Uint64()
  external int rctCutoff;

  @Uint64()
  external int maxWindowCount;

  @Uint64()
  external int aptCutoff;

  @Uint64()
  external int aptWindow;

  @Int32()
  external int rctPassed;

  @Int32()
  external int aptPassed;

  external Pointer<Utf8> summary;
  external Pointer<Utf8> error;
}
