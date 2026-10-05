part of '../../cryptolib.dart';

/// Public metadata of a sealed (Flagship/Fortress) envelope. No secrets.
final class CryptoSealedInfo extends Struct {
  @Uint8()
  external int ok;
  @Uint8()
  external int version;
  @Uint8()
  external int suite;
  @Uint8()
  external int streaming;
  @Array(16)
  external Array<Uint8> fingerprint;
  @Size()
  external int kemCiphertextLen;
}
