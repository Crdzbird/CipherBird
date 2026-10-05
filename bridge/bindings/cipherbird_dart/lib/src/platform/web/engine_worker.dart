part of 'web_platform.dart';

/// A web worker running `cipherbird_worker.js` next to the engine. It loads
/// its own engine instance and answers job messages by id.
final class EngineWorker {
  EngineWorker._(this._worker);

  final JSObject _worker;
  final Map<int, Completer<Object?>> _pending = {};
  var _nextId = 0;

  static Future<EngineWorker>? _starting;

  /// The shared worker, spawned on first use from the loaded engine's URL.
  static Future<EngineWorker> start() =>
      _starting ??= _spawn(WebEngine.current.base);

  static Future<EngineWorker> _spawn(String base) async {
    final script =
        "self.cipherbirdBase='$base';"
        "importScripts('${base}cipherbird_worker.js');";
    final blob = globalContext
        .getProperty<JSFunction>('Blob'.toJS)
        .callAsConstructor<JSObject>(
          [script.toJS].toJS,
          _jsObject({'type': 'text/javascript'}),
        );
    final url = globalContext
        .getProperty<JSObject>('URL'.toJS)
        .callMethod<JSString>('createObjectURL'.toJS, blob);
    final worker = globalContext
        .getProperty<JSFunction>('Worker'.toJS)
        .callAsConstructor<JSObject>(url);
    final instance = EngineWorker._(worker);
    worker['onmessage'] = instance._onMessage.toJS;
    worker['onerror'] = instance._onError.toJS;
    await instance.call('ready', const {});
    return instance;
  }

  /// Sends [op] with [arguments] and completes with the worker's reply.
  Future<Object?> call(String op, Map<String, Object?> arguments) {
    final id = _nextId++;
    final completer = Completer<Object?>();
    _pending[id] = completer;
    _worker.callMethod<JSAny?>(
      'postMessage'.toJS,
      _jsObject({'id': id, 'op': op, 'args': arguments}),
    );
    return completer.future;
  }

  void _onMessage(JSObject event) {
    final data = event.getProperty<JSObject>('data'.toJS);
    final id = data.getProperty<JSNumber>('id'.toJS).toDartInt;
    final completer = _pending.remove(id);
    if (completer == null) {
      return;
    }
    final error = data.getProperty<JSString?>('error'.toJS);
    if (error != null) {
      completer.completeError(Exception(error.toDart));
      return;
    }
    completer.complete(data.getProperty<JSAny?>('result'.toJS).dartify());
  }

  void _onError(JSObject event) {
    final message = event.getProperty<JSString?>('message'.toJS)?.toDart;
    for (final completer in _pending.values) {
      completer.completeError(
        StateError('cipherbird: worker failed: ${message ?? 'unknown'}'),
      );
    }
    _pending.clear();
  }

  static JSObject _jsObject(Map<String, Object?> map) =>
      map.jsify()! as JSObject;
}
