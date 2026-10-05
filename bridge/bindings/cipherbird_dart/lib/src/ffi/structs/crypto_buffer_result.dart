part of '../../cryptolib.dart';

final class CryptoBufferResult extends Struct {
  external CryptoBuffer buf;
  external Pointer<Utf8> error;
}
