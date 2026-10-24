part of 'web_platform.dart';

/// Scratch files for the media entry points, in the engine's in-memory
/// file system: a file is written, the path-taking entry point runs, the
/// result is read back, and both are removed.
final class MediaScratch {
  MediaScratch() : _dir = '/cb${_next++}' {
    WebEngine.current.module.fs.mkdir(_dir);
  }

  static int _next = 0;
  final String _dir;
  int _n = 0;
  final List<String> _paths = [];

  /// Writes [bytes] under a fresh name with [extension] and returns its path.
  String put(String extension, Uint8List bytes) {
    final path = reserve(extension);
    WebEngine.current.module.fs.writeFile(path, bytes.toJS);
    return path;
  }

  /// A fresh path with [extension] for the engine to write to.
  String reserve(String extension) {
    final path = '$_dir/${_n++}.$extension';
    _paths.add(path);
    return path;
  }

  /// Reads [path] back and removes it.
  Uint8List take(String path) {
    final fs = WebEngine.current.module.fs;
    final bytes = Uint8List.fromList(fs.readFile(path).toDart);
    _remove(path);
    return bytes;
  }

  /// Removes every file this scratch created.
  void dispose() {
    for (final p in List.of(_paths)) {
      _remove(p);
    }
  }

  void _remove(String path) {
    final fs = WebEngine.current.module.fs;
    final exists = fs.analyzePath(path).getProperty<JSBoolean>('exists'.toJS);
    if (exists.toDart) {
      fs.unlink(path);
    }
    _paths.remove(path);
  }
}
