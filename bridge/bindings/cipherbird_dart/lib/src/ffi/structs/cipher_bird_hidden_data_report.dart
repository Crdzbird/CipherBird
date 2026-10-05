part of '../../cipher_bird.dart';

/// Heuristic hidden-data probe (`cryptolib_stego_detect_hidden`). Statistical
/// indicators only - never proof of absence.
final class CipherBirdHiddenDataReport extends Struct {
  @Int32()
  external int cipherbirdPayload;

  @Double()
  external double lsbChiSquare;

  @Double()
  external double lsbEmbeddingLikelihood;

  @Uint64()
  external int samplesAnalysed;

  external Pointer<Utf8> note;
  external Pointer<Utf8> error;
}
