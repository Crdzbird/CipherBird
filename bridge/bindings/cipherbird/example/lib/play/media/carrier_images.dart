import 'dart:async';
import 'dart:math';
import 'dart:typed_data';
import 'dart:ui' as ui;

/// A photo-like PPM: a sky gradient, soft waves and sensor-like noise.
Uint8List photoPpm(int size, {int seed = 3, int noise = 24}) {
  final head = 'P6\n$size $size\n255\n'.codeUnits;
  final body = Uint8List(size * size * 3);
  var s = seed | 1;
  int next() {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    return noise == 0 ? 0 : s % noise - noise ~/ 2;
  }

  for (var y = 0; y < size; y++) {
    for (var x = 0; x < size; x++) {
      final i = (y * size + x) * 3;
      final wave = (40 * sin(x / 9.0) * cos(y / 13.0)).round();
      body[i] = (150 + 60 * y ~/ size + wave + next()).clamp(0, 255);
      body[i + 1] = (120 + wave + 90 * x ~/ size + next()).clamp(0, 255);
      body[i + 2] = (200 - 120 * y ~/ size + wave + next()).clamp(0, 255);
    }
  }
  return Uint8List.fromList([...head, ...body]);
}

/// One flat colour: the weakest possible entropy source.
Uint8List flatPpm(int size) => Uint8List.fromList([
  ...'P6\n$size $size\n255\n'.codeUnits,
  ...List<int>.filled(size * size * 3, 90),
]);

/// Pure generator noise in every byte.
Uint8List noisePpm(int size, {int seed = 11}) {
  final body = Uint8List(size * size * 3);
  var s = seed | 1;
  for (var i = 0; i < body.length; i++) {
    s ^= (s << 13) & 0xFFFFFFFF;
    s ^= s >> 17;
    s ^= (s << 5) & 0xFFFFFFFF;
    body[i] = s & 0xFF;
  }
  return Uint8List.fromList(
    ['P6\n$size $size\n255\n'.codeUnits, body].expand((b) => b).toList(),
  );
}

/// An image for display when [bytes] are a PPM or a format the platform
/// decodes (PNG, JPEG, GIF, BMP, WebP); null for sounds and other files.
Future<ui.Image?> previewImage(Uint8List bytes, String extension) async {
  if (extension == 'ppm') {
    return ppmImage(bytes);
  }
  if (!const {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}.contains(extension)) {
    return null;
  }
  try {
    final codec = await ui.instantiateImageCodec(bytes);
    return (await codec.getNextFrame()).image;
  } on Object {
    return null;
  }
}

/// Decodes a binary PPM into an image for display.
Future<ui.Image> ppmImage(Uint8List ppm) {
  final tokens = <String>[];
  var i = 0;
  var token = StringBuffer();
  while (tokens.length < 4 && i < ppm.length) {
    final c = ppm[i++];
    final blank = c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09;
    if (blank && token.isNotEmpty) {
      tokens.add(token.toString());
      token = StringBuffer();
      continue;
    }
    if (!blank) {
      token.writeCharCode(c);
    }
  }
  final w = int.parse(tokens[1]);
  final h = int.parse(tokens[2]);
  final rgba = Uint8List(w * h * 4);
  for (var p = 0; p < w * h; p++) {
    rgba[p * 4] = ppm[i + p * 3];
    rgba[p * 4 + 1] = ppm[i + p * 3 + 1];
    rgba[p * 4 + 2] = ppm[i + p * 3 + 2];
    rgba[p * 4 + 3] = 255;
  }
  final done = Completer<ui.Image>();
  ui.decodeImageFromPixels(rgba, w, h, ui.PixelFormat.rgba8888, done.complete);
  return done.future;
}
