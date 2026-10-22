part of '../native_platform.dart';

/// Where a live entropy source stands (`cryptolib_live_entropy_status`).
final class CipherBirdLiveStatus extends Struct {
  @Uint64()
  external int chunksFed;

  @Uint64()
  external int chunksAccepted;

  @Uint64()
  external int chunksRejected;

  @Uint64()
  external int bytesFed;

  @Uint64()
  external int reseeds;

  @Double()
  external double creditedBitsTotal;

  @Double()
  external double creditedBitsSinceReseed;

  @Double()
  external double minCreditedBits;

  @Int32()
  external int ready;

  @Double()
  external double lastMinEntropyPerByte;

  @Uint64()
  external int lastLongestRun;

  @Uint64()
  external int lastRctCutoff;

  external Pointer<Utf8> lastReason;
  external Pointer<Utf8> error;
}
