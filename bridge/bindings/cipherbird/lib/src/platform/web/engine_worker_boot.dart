part of 'web_platform.dart';

JSObject _jsObject(Map<String, Object?> map) => map.jsify()! as JSObject;

/// Spawns the engine worker from verified bytes: `cipherbird.js` and
/// `cipherbird_worker.js` are fetched with their integrity digests and joined
/// into one blob, so the worker never imports a script by URL and nothing is
/// interpolated into its source.
Future<JSObject> _spawnWorker(String base) async {
  final engine = await _fetchVerifiedText(
    '${base}cipherbird.js',
    EngineIntegrity.engine,
  );
  final script = await _fetchVerifiedText(
    '${base}cipherbird_worker.js',
    EngineIntegrity.worker,
  );
  final blob = globalContext
      .getProperty<JSFunction>('Blob'.toJS)
      .callAsConstructor<JSObject>(
        ['$engine\n$script'.toJS].toJS,
        _jsObject({'type': 'text/javascript'}),
      );
  final url = globalContext
      .getProperty<JSObject>('URL'.toJS)
      .callMethod<JSString>('createObjectURL'.toJS, blob);
  return globalContext
      .getProperty<JSFunction>('Worker'.toJS)
      .callAsConstructor<JSObject>(url);
}

/// The worker's first message: the verified `.wasm` bytes, transferred, from
/// which it instantiates its own engine copy.
Future<void> _initWorker(EngineWorker worker, String base) async {
  final wasm = await _fetchVerified(
    '${base}cipherbird.wasm',
    EngineIntegrity.wasm,
  );
  final args = JSObject();
  args['wasm'] = wasm;
  await worker._post('init', args, [wasm]);
}
