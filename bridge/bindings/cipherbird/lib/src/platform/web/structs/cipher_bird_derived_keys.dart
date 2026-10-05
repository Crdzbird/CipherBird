part of '../web_platform.dart';

/// Web view of the C `CryptoDerivedKeys` struct.
final class CipherBirdDerivedKeys extends Struct {
  const CipherBirdDerivedKeys._(super.memory, super.base);

  static CipherBirdDerivedKeys _new(Memory memory, int base) =>
      CipherBirdDerivedKeys._(memory, base);

  /// Byte size under wasm32.
  static const int size = 48;

  CipherBirdBuffer get symmetricKey => CipherBirdBuffer._(_memory, _base + 0);
  CipherBirdBuffer get vaultMasterKey => CipherBirdBuffer._(_memory, _base + 8);
  CipherBirdBuffer get signingSeed => CipherBirdBuffer._(_memory, _base + 16);
  CipherBirdBuffer get boxSeed => CipherBirdBuffer._(_memory, _base + 24);
  CipherBirdBuffer get streamKey => CipherBirdBuffer._(_memory, _base + 32);
  CipherBirdBuffer get rawEntropy => CipherBirdBuffer._(_memory, _base + 40);
}
