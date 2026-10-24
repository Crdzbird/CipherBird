part of 'stego_playground.dart';

extension on StegoPlayground {
  String get _ext => switch (_carrier.value) {
    'picked file' =>
      _picked == null ? 'bin' : carrierExtension(_picked!.name) ?? 'bin',
    final c when c.contains('WAV') => 'wav',
    _ => 'ppm',
  };

  /// The carrier format the engine dispatches on, from the extension.
  MediaFormat get _format => switch (_ext) {
    'ppm' => MediaFormat.ppmImage,
    'wav' => MediaFormat.wavAudio,
    'png' => MediaFormat.pngImage,
    'bmp' => MediaFormat.bmpImage,
    'gif' => MediaFormat.gifImage,
    'jpg' || 'jpeg' => MediaFormat.jpegImage,
    'flac' => MediaFormat.flacAudio,
    'mp3' => MediaFormat.mp3Audio,
    'mp4' => MediaFormat.mp4Video,
    'avi' => MediaFormat.aviVideo,
    'crvf' => MediaFormat.crvfVideo,
    _ => throw StateError(
      'pick a PPM, PNG, BMP, GIF, JPEG, WAV, FLAC, MP3, MP4, AVI or CRVF file',
    ),
  };

  Uint8List _carrierBytes() => switch (_carrier.value) {
    'photo 512x512 PPM' => photoPpm(512),
    'photo 1024x1024 PPM' => photoPpm(1024),
    'photo 256x256 PPM' => photoPpm(256),
    'tone 10 s WAV' => toneWav(10),
    'tone 2 s WAV' => toneWav(2),
    _ => _pickedBytes(),
  };

  Uint8List _pickedBytes() {
    final p = _picked;
    if (p == null) {
      throw StateError('press Pick a file first');
    }
    return p.bytes;
  }

  /// Chooses any file on the device as the carrier: PPM, PNG, BMP, GIF,
  /// JPEG, WAV, FLAC, MP3, MP4, AVI or CRVF.
  Future<void> pickFile() => attempt('pick', () async {
    final p = await pickMedia();
    if (p == null) {
      say('no file picked');
      return;
    }
    _picked = p;
    _carrier.selected.value = 'picked file';
    say('picked ${p.name}: ${p.bytes.length} bytes; press New carrier');
  });
}
