part of '../../cipher_bird.dart';

/// Structural validity + detected format of a media file (`cryptolib_stego_inspect`).
final class CipherBirdFileInspection extends Struct {
  @Int32()
  external int parses;

  @Uint8()
  external int format;

  @Int32()
  external int extMatches;

  @Uint64()
  external int width;

  @Uint64()
  external int height;

  @Uint64()
  external int fileSize;

  external Pointer<Utf8> detail;
  external Pointer<Utf8> error;
}
