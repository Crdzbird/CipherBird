part of 'cryptolib.dart';

class Packet {
  final Uint8List ciphertext;
  final Uint8List signature;
  final Uint8List kdfSalt;

  Packet({
    required this.ciphertext,
    required this.signature,
    required this.kdfSalt,
  });
}

/// DerivedKeysResult holds 6 domain-separated keys from a media file.
class DerivedKeysResult {
  final Uint8List symmetricKey;
  final Uint8List vaultMasterKey;
  final Uint8List signingSeed;
  final Uint8List boxSeed;
  final Uint8List streamKey;
  final Uint8List rawEntropy;

  DerivedKeysResult({
    required this.symmetricKey,
    required this.vaultMasterKey,
    required this.signingSeed,
    required this.boxSeed,
    required this.streamKey,
    required this.rawEntropy,
  });
}

/// EntropyInfoResult holds metadata about an entropy source.
class EntropyInfoResult {
  final String path;
  final int fileSize;
  final int chunksRead;
  final double entropyBits;

  EntropyInfoResult({
    required this.path,
    required this.fileSize,
    required this.chunksRead,
    required this.entropyBits,
  });
}

/// KeyPairResult holds a public/secret key pair.
class KeyPairResult {
  final Uint8List publicKey;
  final Uint8List secretKey;

  KeyPairResult({required this.publicKey, required this.secretKey});
}

/// AsymBundleResult holds X25519 + Ed25519 key pairs.
class AsymBundleResult {
  final Uint8List boxPublic;
  final Uint8List boxSecret;
  final Uint8List signPublic;
  final Uint8List signSecret;

  AsymBundleResult({
    required this.boxPublic,
    required this.boxSecret,
    required this.signPublic,
    required this.signSecret,
  });
}
