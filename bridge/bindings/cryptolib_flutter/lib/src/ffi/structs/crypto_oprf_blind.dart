part of '../../cryptolib.dart';

final class CryptoOprfBlind extends Struct {
  external CryptoBuffer blind;
  external CryptoBuffer blindedElement;
  external Pointer<Utf8> error;
}
