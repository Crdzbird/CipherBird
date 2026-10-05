part of 'web_platform.dart';

const String _packageName = 'cipherbird_dart';

/// Where the engine is looked for when no URL is given: the Flutter web
/// asset path, then the plain Dart package path.
List<String> engineCandidates() => [
  'assets/packages/$_packageName/assets/cipherbird.js',
  'packages/$_packageName/assets/cipherbird.js',
];

/// Loads and instantiates the WebAssembly engine once. [library] is the URL
/// of `cipherbird.js` (its `.wasm` sits next to it); the `CIPHERBIRD_LIBRARY`
/// compile-time define and the package asset paths are tried otherwise.
Future<void> prepareEngine(String? library) async {
  if (WebEngine.isLoaded) {
    return;
  }
  const defined = String.fromEnvironment('CIPHERBIRD_LIBRARY');
  final candidates = [
    if (library != null && library.isNotEmpty) library,
    if (defined.isNotEmpty) defined,
    ...engineCandidates(),
  ];
  Object? lastError;
  for (final url in candidates) {
    try {
      WebEngine._current = WebEngine._(await _instantiate(url));
      return;
    } on Object catch (error) {
      lastError = error;
    }
  }
  throw StateError('cipherbird: could not load the engine: $lastError');
}

Future<EngineModule> _instantiate(String url) async {
  await _injectScript(url);
  final factory = globalContext.getProperty<JSFunction?>(
    'createCipherBird'.toJS,
  );
  if (factory == null) {
    throw StateError('cipherbird: $url did not define createCipherBird');
  }
  final base = url.substring(0, url.lastIndexOf('/') + 1);
  final options = JSObject();
  options['locateFile'] = ((String file) => '$base$file').toJS;
  final promise = factory.callAsFunction(null, options);
  if (promise == null) {
    throw StateError('cipherbird: createCipherBird returned nothing');
  }
  return EngineModule._(await (promise as JSPromise<JSObject>).toDart);
}

Future<void> _injectScript(String url) {
  final completer = Completer<void>();
  final document = globalContext.getProperty<JSObject>('document'.toJS);
  final script = document.callMethod<JSObject>(
    'createElement'.toJS,
    'script'.toJS,
  );
  script['src'] = url.toJS;
  script['onload'] = (JSAny? event) {
    completer.complete();
  }.toJS;
  script['onerror'] = ((JSAny? event) {
    completer.completeError(StateError('cipherbird: failed to fetch $url'));
  }).toJS;
  document
      .getProperty<JSObject>('head'.toJS)
      .callMethod<JSAny?>('appendChild'.toJS, script);
  return completer.future;
}
