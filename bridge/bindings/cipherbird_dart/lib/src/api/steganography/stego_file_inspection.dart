part of '../../cryptolib.dart';

/// Structural inspection of a media file - is it a valid carrier, and does its
/// real content match its extension?
final class StegoFileInspection {
  const StegoFileInspection({
    required this.parses,
    required this.format,
    required this.extensionMatches,
    required this.width,
    required this.height,
    required this.fileSize,
    required this.detail,
  });

  /// The file is recognised and structurally plausible as a carrier.
  final bool parses;

  /// Format detected from the file's content.
  final MediaFormat format;

  /// Content format agrees with the filename extension. A `false` here on an
  /// otherwise valid file means the file was renamed - worth noticing.
  final bool extensionMatches;

  /// Pixel width (images only; 0 otherwise).
  final int width;

  /// Pixel height (images only; 0 otherwise).
  final int height;

  /// Size on disk, in bytes.
  final int fileSize;

  /// Human-readable summary of what was found.
  final String detail;
}
