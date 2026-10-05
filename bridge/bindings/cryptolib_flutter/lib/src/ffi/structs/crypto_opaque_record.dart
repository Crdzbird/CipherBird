part of '../../cryptolib.dart';

final class CryptoOpaqueRecord extends Struct {
  external CryptoBuffer record;
  external CryptoBuffer exportKey;
  external Pointer<Utf8> error;
}
