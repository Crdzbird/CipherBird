part of 'native_platform.dart';

const _packageNames = ['cipherbird_dart', 'cipherbird'];

String? _bundledLibraryPath() {
  final slot = _nativeSlot();
  if (slot == null) return null;
  final roots = <String>[
    ..._packageRootsFromConfig(),
    Directory.current.path,
    if (Platform.script.scheme == 'file')
      File.fromUri(Platform.script).parent.parent.path,
  ];
  for (final root in roots) {
    final candidate = '$root/native/$slot/${_libraryFileName()}';
    if (File(candidate).existsSync()) return candidate;
  }
  return null;
}

String? _nativeSlot() {
  final os = Platform.isMacOS
      ? 'darwin'
      : Platform.isLinux
      ? 'linux'
      : Platform.isWindows
      ? 'windows'
      : null;
  if (os == null) return null;
  final abi = Abi.current().toString();
  if (abi.endsWith('arm64')) return '$os-arm64';
  if (abi.endsWith('x64')) return '$os-x64';
  return null;
}

String _libraryFileName() => Platform.isMacOS
    ? 'libcipherbird.dylib'
    : Platform.isWindows
    ? 'cipherbird.dll'
    : 'libcipherbird.so';

List<String> _packageRootsFromConfig() {
  final config = File(
    '${Directory.current.path}/.dart_tool/package_config.json',
  );
  if (!config.existsSync()) return const [];
  final packages =
      (jsonDecode(config.readAsStringSync())
          as Map<String, dynamic>)['packages'];
  if (packages is! List) return const [];
  return [
    for (final entry in packages.whereType<Map<String, dynamic>>())
      if (_packageNames.contains(entry['name']))
        config.parent.uri.resolve(entry['rootUri'] as String).toFilePath(),
  ];
}
