import 'dart:io';
import 'dart:typed_data';

/// Scratch files of a playground, kept in a private temporary folder.
final class PlayFiles {
  PlayFiles(String tag)
    : _dir = Directory.systemTemp.createTempSync('cipherbird_$tag');

  final Directory _dir;

  String path(String name) => '${_dir.path}/$name';

  String write(String name, Uint8List bytes) {
    final p = path(name);
    File(p).writeAsBytesSync(bytes);
    return p;
  }

  Uint8List read(String name) => File(path(name)).readAsBytesSync();

  /// XORs [count] bytes with [mask], spread over the middle three fifths of
  /// the file past its [header]; returns how many bytes changed.
  int corrupt(
    String name, {
    required int header,
    required int count,
    required int mask,
  }) {
    final bytes = read(name);
    final body = bytes.length - header;
    if (body <= 0) {
      return 0;
    }
    final start = header + body ~/ 5;
    final span = body * 3 ~/ 5;
    final step = span ~/ count;
    if (step < 1) {
      return 0;
    }
    for (var i = 0; i < count; i++) {
      bytes[start + i * step] ^= mask;
    }
    File(path(name)).writeAsBytesSync(bytes);
    return count;
  }
}
