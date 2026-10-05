part of '../cryptolib.dart';

/// EntropyInfoResult holds metadata about an entropy source.
final class EntropyInfoResult {
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
