part of '../cipher_bird.dart';

/// Media container format inferred from a file's actual bytes (not its
/// extension). Returned by `CipherBirdStegoAdvanced.stegoInspect`.
enum MediaFormat {
  ppmImage(0),
  wavAudio(1),
  crvfVideo(2),
  bmpImage(3),
  pngImage(4),
  flacAudio(5),
  aviVideo(6),
  gifImage(7),
  jpegImage(8),
  mp3Audio(9),
  mp4Video(10),

  /// Content did not match any supported carrier format.
  unknown(0xFF);

  const MediaFormat(this.value);

  /// Wire value used by the C ABI.
  final int value;

  /// Map a raw C ABI value, falling back to [unknown].
  static MediaFormat fromValue(int v) => MediaFormat.values.firstWhere(
    (f) => f.value == v,
    orElse: () => MediaFormat.unknown,
  );
}
