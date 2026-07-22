part of '../cryptolib.dart';

// Raw C struct layouts marshalled across the FFI boundary (internal).

final class CryptoBuffer extends Struct {
  external Pointer<Uint8> data;

  @Size()
  external int len;
}

final class CryptoBufferResult extends Struct {
  external CryptoBuffer buf;
  external Pointer<Utf8> error;
}

final class CryptoResult extends Struct {
  @Int32()
  external int ok;
  external Pointer<Utf8> error;
}

final class CryptoPacket extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer signature;
  external CryptoBuffer kdfSalt;
}

final class CryptoKeyPair extends Struct {
  external CryptoBuffer publicKey;
  external CryptoBuffer secretKey;
}

final class CryptoKemEncapsResult extends Struct {
  external CryptoBuffer ciphertext;
  external CryptoBuffer sharedSecret;
}

final class CryptoAsymBundle extends Struct {
  external CryptoBuffer boxPublic;
  external CryptoBuffer boxSecret;
  external CryptoBuffer signPublic;
  external CryptoBuffer signSecret;
}

final class CryptoDerivedKeys extends Struct {
  external CryptoBuffer symmetricKey;
  external CryptoBuffer vaultMasterKey;
  external CryptoBuffer signingSeed;
  external CryptoBuffer boxSeed;
  external CryptoBuffer streamKey;
  external CryptoBuffer rawEntropy;
}

final class CryptoEntropyInfo extends Struct {
  external Pointer<Utf8> path;

  @Uint64()
  external int fileSize;

  @Uint64()
  external int chunksRead;

  @Double()
  external double entropyBits;
}

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
