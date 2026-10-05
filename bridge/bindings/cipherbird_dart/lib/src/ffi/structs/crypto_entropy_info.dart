part of '../../cryptolib.dart';

final class CryptoEntropyInfo extends Struct {
  external Pointer<Utf8> path;

  @Uint64()
  external int fileSize;

  @Uint64()
  external int chunksRead;

  @Double()
  external double entropyBits;
}
