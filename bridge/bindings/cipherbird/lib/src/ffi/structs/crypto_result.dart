part of '../../cryptolib.dart';

final class CryptoResult extends Struct {
  @Int32()
  external int ok;
  external Pointer<Utf8> error;
}
