part of '../web_platform.dart';

/// wasm32 byte sizes of the struct views, for `sizeOf` and `calloc`.
final Map<Type, int> structSizes = {
  CipherBirdBuffer: CipherBirdBuffer.size,
  CipherBirdResult: CipherBirdResult.size,
  CipherBirdBufferResult: CipherBirdBufferResult.size,
  CipherBirdKeyPair: CipherBirdKeyPair.size,
  CipherBirdAsymBundle: CipherBirdAsymBundle.size,
  CipherBirdPacket: CipherBirdPacket.size,
  CipherBirdDerivedKeys: CipherBirdDerivedKeys.size,
  CipherBirdEntropyInfo: CipherBirdEntropyInfo.size,
  CipherBirdSealedInfo: CipherBirdSealedInfo.size,
  CipherBirdKemEncapsResult: CipherBirdKemEncapsResult.size,
  CipherBirdFrostKeyGen: CipherBirdFrostKeyGen.size,
  CipherBirdFrostCommit: CipherBirdFrostCommit.size,
  CipherBirdOprfBlind: CipherBirdOprfBlind.size,
  CipherBirdOpaqueRecord: CipherBirdOpaqueRecord.size,
  CipherBirdOpaqueKe1: CipherBirdOpaqueKe1.size,
  CipherBirdOpaqueKe2: CipherBirdOpaqueKe2.size,
  CipherBirdOpaqueKe3: CipherBirdOpaqueKe3.size,
  CipherBirdFileInspection: CipherBirdFileInspection.size,
  CipherBirdHiddenDataReport: CipherBirdHiddenDataReport.size,
  CipherBirdHealthReport: CipherBirdHealthReport.size,
};

final Map<Type, Struct Function(Memory memory, int base)> _factories = {
  CipherBirdBuffer: CipherBirdBuffer._new,
  CipherBirdResult: CipherBirdResult._new,
  CipherBirdBufferResult: CipherBirdBufferResult._new,
  CipherBirdKeyPair: CipherBirdKeyPair._new,
  CipherBirdAsymBundle: CipherBirdAsymBundle._new,
  CipherBirdPacket: CipherBirdPacket._new,
  CipherBirdDerivedKeys: CipherBirdDerivedKeys._new,
  CipherBirdEntropyInfo: CipherBirdEntropyInfo._new,
  CipherBirdSealedInfo: CipherBirdSealedInfo._new,
  CipherBirdKemEncapsResult: CipherBirdKemEncapsResult._new,
  CipherBirdFrostKeyGen: CipherBirdFrostKeyGen._new,
  CipherBirdFrostCommit: CipherBirdFrostCommit._new,
  CipherBirdOprfBlind: CipherBirdOprfBlind._new,
  CipherBirdOpaqueRecord: CipherBirdOpaqueRecord._new,
  CipherBirdOpaqueKe1: CipherBirdOpaqueKe1._new,
  CipherBirdOpaqueKe2: CipherBirdOpaqueKe2._new,
  CipherBirdOpaqueKe3: CipherBirdOpaqueKe3._new,
  CipherBirdFileInspection: CipherBirdFileInspection._new,
  CipherBirdHiddenDataReport: CipherBirdHiddenDataReport._new,
  CipherBirdHealthReport: CipherBirdHealthReport._new,
};

/// A view of struct [T] at [base] in [memory].
T structView<T extends Struct>(Memory memory, int base) {
  final make = _factories[T];
  if (make == null) {
    throw ArgumentError('cipherbird: unknown struct type $T');
  }
  return make(memory, base) as T;
}
