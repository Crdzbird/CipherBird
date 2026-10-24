import 'dart:typed_data';

/// A copy of [bytes] with [count] positions XORed with [mask], spread over
/// the middle three fifths past [header]; returns the copy and how many
/// bytes changed.
(Uint8List, int) damaged(
  Uint8List bytes, {
  required int header,
  required int count,
  required int mask,
}) {
  final out = Uint8List.fromList(bytes);
  final body = out.length - header;
  if (body <= 0) {
    return (out, 0);
  }
  final start = header + body ~/ 5;
  final step = (body * 3 ~/ 5) ~/ count;
  if (step < 1) {
    return (out, 0);
  }
  for (var i = 0; i < count; i++) {
    out[start + i * step] ^= mask;
  }
  return (out, count);
}

/// The carrier format a picked file's extension names, or null.
String? carrierExtension(String name) {
  final dot = name.lastIndexOf('.');
  final ext = dot < 0 ? '' : name.substring(dot + 1).toLowerCase();
  const known = {
    'ppm',
    'png',
    'bmp',
    'gif',
    'jpg',
    'jpeg',
    'wav',
    'flac',
    'mp3',
    'mp4',
    'avi',
    'crvf',
  };
  return known.contains(ext) ? ext : null;
}
