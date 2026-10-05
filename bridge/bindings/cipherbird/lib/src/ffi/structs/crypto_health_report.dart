part of '../../cipher_bird.dart';

/// SP 800-90B style health assessment of a file's entropy
/// (`cryptolib_entropy_assess_file_health`).
final class CryptoHealthReport extends Struct {
  @Double()
  external double minEntropyPerByte;

  @Uint64()
  external int longestRun;

  @Uint64()
  external int maxWindowCount;

  @Int32()
  external int rctPassed;

  @Int32()
  external int aptPassed;

  external Pointer<Utf8> error;
}
