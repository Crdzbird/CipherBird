part of '../cipher_bird.dart';

/// AsymBundleResult holds X25519 + Ed25519 key pairs.
final class AsymBundleResult {
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
