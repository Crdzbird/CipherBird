part of 'web_platform.dart';

const String _packageName = 'cipherbird';

/// Where the engine is looked for when no URL is given: the Flutter web
/// asset path, then the plain Dart package path.
List<String> engineCandidates() => [
  'assets/packages/$_packageName/assets/cipherbird.js',
  'packages/$_packageName/assets/cipherbird.js',
];

/// The WebAssembly engine must be fetched and compiled before first use.
const bool engineLoadsAsynchronously = true;

Future<void>? _inFlight;

/// Loads and instantiates the WebAssembly engine once. [library] is the URL
/// of `cipherbird.js` (its `.wasm` sits next to it); the `CIPHERBIRD_LIBRARY`
/// compile-time define and the package asset paths are tried otherwise.
/// Every file is checked against the digests in [EngineIntegrity].
/// Concurrent callers share one load; a caller with an explicit [library]
/// retries with it only if the shared load failed.
Future<void> prepareEngine(String? library, {bool workerOnly = false}) async {
  if (workerOnly) {
    WebEngine.workerOnly = true;
  }
  if (WebEngine.isLoaded || WebEngine.workerBase != null) {
    return;
  }
  if (!WebEngine.workerOnly && adoptPageEngine()) {
    return;
  }
  final shared = _inFlight;
  if (shared != null) {
    try {
      await shared;
      return;
    } on Object catch (_) {
      if (library == null || library.isEmpty) {
        rethrow;
      }
    }
  }
  final load = _load(library);
  _inFlight = load;
  try {
    await load;
  } on Object catch (_) {
    _inFlight = null;
    rethrow;
  }
}

Future<void> _load(String? library) async {
  if (library == null || library.isEmpty) {
    if (await awaitPageEngine()) {
      return;
    }
  }
  const defined = String.fromEnvironment('CIPHERBIRD_LIBRARY');
  final candidates = [
    if (library != null && library.isNotEmpty) library,
    if (defined.isNotEmpty) defined,
    ...engineCandidates(),
  ];
  final errors = <String>[];
  for (final url in candidates) {
    try {
      final absolute = Uri.base.resolve(url).toString();
      final base = absolute.substring(0, absolute.lastIndexOf('/') + 1);
      if (WebEngine.workerOnly) {
        WebEngine.workerBase = base;
        await EngineWorker.start();
        return;
      }
      WebEngine._current = WebEngine._(await _instantiate(absolute), base);
      await EngineWorker.start();
      return;
    } on Object catch (error) {
      WebEngine.workerBase = null;
      errors.add('$url: $error');
    }
  }
  throw StateError('cipherbird: could not load the engine: $errors');
}
