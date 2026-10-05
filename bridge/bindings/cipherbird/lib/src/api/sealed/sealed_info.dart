part of '../../cipher_bird.dart';

/// Public metadata carried by a sealed envelope (no secrets).
final class SealedInfo {
  final int version;

  /// Assurance tier this envelope was sealed with.
  final SealedTier suite;
  final bool streaming;
  final Uint8List fingerprint;
  final int kemCiphertextLen;
  SealedInfo({
    required this.version,
    required this.suite,
    required this.streaming,
    required this.fingerprint,
    required this.kemCiphertextLen,
  });
}
