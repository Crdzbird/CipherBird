part of 'entropy_playground.dart';

extension on EntropyPlayground {
  String get _ext => switch (_source.value) {
    'picked file' => _picked?.extension ?? 'bin',
    'tone WAV' => 'wav',
    _ => 'ppm',
  };

  Uint8List _sourceBytes() => switch (_source.value) {
    'photo PPM' => photoPpm(256),
    'flat colour PPM (weak)' => flatPpm(256),
    'noise PPM' => noisePpm(256),
    'tone WAV' => toneWav(4),
    _ => _pickedBytes(),
  };

  Uint8List _pickedBytes() {
    final p = _picked;
    if (p == null) {
      throw StateError('press Pick a file first');
    }
    return p.bytes;
  }

  /// Chooses any file on the device as the source: a photo, a recording, a
  /// video, or anything else, since the harvest reads bytes.
  Future<void> pickFile() => attempt('pick', () async {
    final p = await pickMedia();
    if (p == null) {
      say('no file picked');
      return;
    }
    _picked = p;
    _source.selected.value = 'picked file';
    say('picked ${p.name}: ${p.bytes.length} bytes; press New source');
  });
}
