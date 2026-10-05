part of '../cipher_bird.dart';

/// DerivedKeysResult holds 6 domain-separated keys from a media file.
final class DerivedKeysResult {
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
