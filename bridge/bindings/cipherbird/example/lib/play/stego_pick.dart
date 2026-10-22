part of 'stego_playground.dart';

extension on StegoPlayground {
  String get _ext => switch (_carrier.value) {
    'picked file' => _picked?.extension ?? 'bin',
    final c when c.contains('WAV') => 'wav',
    _ => 'ppm',
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
  Future<void> pickFile() => attemptWithFiles('pick', () async {
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
