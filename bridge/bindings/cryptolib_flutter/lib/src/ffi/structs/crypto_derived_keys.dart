part of '../../cryptolib.dart';

final class CryptoDerivedKeys extends Struct {
  external CryptoBuffer symmetricKey;
  external CryptoBuffer vaultMasterKey;
  external CryptoBuffer signingSeed;
  external CryptoBuffer boxSeed;
  external CryptoBuffer streamKey;
  external CryptoBuffer rawEntropy;
}
