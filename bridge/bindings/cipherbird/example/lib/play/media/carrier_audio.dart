import 'dart:math';
import 'dart:typed_data';

/// A 16-bit mono WAV of two tones with a little noise, [seconds] long.
Uint8List toneWav(double seconds, {int seed = 7}) {
  const rate = 44100;
  final n = (rate * seconds).round();
  final data = ByteData(44 + n * 2);
  void tag(int offset, String s) {
    for (var i = 0; i < 4; i++) {
      data.setUint8(offset + i, s.codeUnitAt(i));
    }
  }

  tag(0, 'RIFF');
  data.setUint32(4, 36 + n * 2, Endian.little);
  tag(8, 'WAVE');
  tag(12, 'fmt ');
  data.setUint32(16, 16, Endian.little);
  data.setUint16(20, 1, Endian.little);
  data.setUint16(22, 1, Endian.little);
  data.setUint32(24, rate, Endian.little);
  data.setUint32(28, rate * 2, Endian.little);
  data.setUint16(32, 2, Endian.little);
  data.setUint16(34, 16, Endian.little);
  tag(36, 'data');
  data.setUint32(40, n * 2, Endian.little);
  final random = Random(seed);
  for (var i = 0; i < n; i++) {
    final t = i / rate;
    final v =
        9000 * sin(2 * pi * 440 * t) +
        3000 * sin(2 * pi * 1250 * t) +
        random.nextInt(600) -
        300;
    data.setInt16(44 + i * 2, v.round(), Endian.little);
  }
  return data.buffer.asUint8List();
}
