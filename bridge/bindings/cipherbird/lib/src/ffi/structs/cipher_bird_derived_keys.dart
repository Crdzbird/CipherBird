part of '../../cipher_bird.dart';

final class CipherBirdDerivedKeys extends Struct {
  external CipherBirdBuffer symmetricKey;
  external CipherBirdBuffer vaultMasterKey;
  external CipherBirdBuffer signingSeed;
  external CipherBirdBuffer boxSeed;
  external CipherBirdBuffer streamKey;
  external CipherBirdBuffer rawEntropy;
}
