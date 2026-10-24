part of 'native_platform.dart';

/// Scratch files for the media entry points, in a private temporary
/// directory: a file is written, the path-taking entry point runs, the
/// result is read back, and both are overwritten and removed.
final class MediaScratch {
  MediaScratch() : _dir = Directory.systemTemp.createTempSync('cipherbird_');

  final Directory _dir;
  int _n = 0;

  /// Writes [bytes] under a fresh name with [extension] and returns its path.
  String put(String extension, Uint8List bytes) {
    final path = reserve(extension);
    File(path).writeAsBytesSync(bytes, flush: true);
    return path;
  }

  /// A fresh path with [extension] for the engine to write to.
  String reserve(String extension) => '${_dir.path}/${_n++}.$extension';

  /// Reads [path] back, overwrites it with zeros and removes it.
  Uint8List take(String path) {
    final file = File(path);
    final bytes = file.readAsBytesSync();
    _wipe(file);
    return bytes;
  }

  /// Overwrites and removes every file this scratch created.
  void dispose() {
    if (_dir.existsSync()) {
      for (final f in _dir.listSync().whereType<File>()) {
        _wipe(f);
      }
      _dir.deleteSync(recursive: true);
    }
  }

  void _wipe(File file) {
    if (!file.existsSync()) {
      return;
    }
    file.writeAsBytesSync(Uint8List(file.lengthSync()), flush: true);
    file.deleteSync();
  }
}
