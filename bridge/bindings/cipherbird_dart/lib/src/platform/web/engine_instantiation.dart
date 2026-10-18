part of 'web_platform.dart';

final Set<String> _injectedEngines = {};

JSFunction? _readFactory() =>
    globalContext.getProperty<JSFunction?>('createCipherBird'.toJS);

/// A `createCipherBird` already on the page is only acceptable as a plain
/// writable binding, the kind a script tag's `var` creates, because the
/// verified script then overwrites it. A read-only or accessor property
/// would survive the verified script and is refused.
void _checkPageFactory() {
  final descriptor = globalContext
      .getProperty<JSObject>('Object'.toJS)
      .callMethod<JSObject?>(
        'getOwnPropertyDescriptor'.toJS,
        globalContext,
        'createCipherBird'.toJS,
      );
  if (descriptor == null) {
    return;
  }
  final writable =
      descriptor.getProperty<JSBoolean?>('writable'.toJS)?.toDart ?? false;
  if (!writable) {
    throw StateError(
      'cipherbird: createCipherBird is defined by the page in a way the '
      'verified engine script cannot replace',
    );
  }
}

/// The `instantiateWasm` hook of the engine factory: instantiates the
/// verified [bytes] instead of letting the glue fetch the file itself.
/// [failure] receives an instantiation error, which the glue has no path
/// to report.
JSFunction _instantiateFromBytes(
  JSArrayBuffer bytes,
  Completer<void> failure,
) => ((JSObject imports, JSFunction onInstance) {
  globalContext
      .getProperty<JSObject>('WebAssembly'.toJS)
      .callMethod<JSPromise<JSObject>>('instantiate'.toJS, bytes, imports)
      .callMethod<JSAny?>(
        'then'.toJS,
        ((JSObject result) {
          onInstance.callAsFunction(
            null,
            result.getProperty<JSObject>('instance'.toJS),
          );
        }).toJS,
        ((JSAny? error) {
          failure.completeError(
            StateError('cipherbird: engine instantiation failed: $error'),
          );
        }).toJS,
      );
  return JSObject();
}).toJS;

/// Loads `cipherbird.js` from [url] with its integrity digest, fetches the
/// `.wasm` next to it the same way and instantiates the engine from those
/// verified bytes.
Future<EngineModule> _instantiate(String url) async {
  if (_injectedEngines.add(url)) {
    _checkPageFactory();
    await _injectScript(url, EngineIntegrity.engine);
  }
  final factory = _readFactory();
  if (factory == null) {
    throw StateError('cipherbird: $url did not define createCipherBird');
  }
  final base = url.substring(0, url.lastIndexOf('/') + 1);
  final wasm = await _fetchVerified(
    '${base}cipherbird.wasm',
    EngineIntegrity.wasm,
  );
  final failure = Completer<void>();
  final options = JSObject();
  options['instantiateWasm'] = _instantiateFromBytes(wasm, failure);
  options['locateFile'] = ((String file) => '$base$file').toJS;
  final promise = factory.callAsFunction(null, options);
  if (promise == null) {
    throw StateError('cipherbird: createCipherBird returned nothing');
  }
  final module = await Future.any([
    (promise as JSPromise<JSObject>).toDart,
    failure.future.then((_) => throw StateError('unreachable')),
  ]);
  return EngineModule._(module);
}
