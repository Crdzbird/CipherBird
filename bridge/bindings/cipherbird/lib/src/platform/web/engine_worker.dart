part of 'web_platform.dart';

/// A web worker running `cipherbird_worker.js` on its own engine instance,
/// built from verified bytes. It answers job messages by id.
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
    final worker = await _spawnWorker(base);
    final instance = EngineWorker._(worker);
    worker['onmessage'] = instance._onMessage.toJS;
    worker['onerror'] = instance._onError.toJS;
    await _initWorker(instance, base);
    return instance;
  }

  /// Sends [op] with [arguments] and completes with the worker's reply.
  Future<Object?> call(String op, Map<String, Object?> arguments) =>
      _post(op, _jsObject(arguments), const <JSAny>[]);

  Future<Object?> _post(String op, JSObject args, List<JSAny> transfer) {
    final id = _nextId++;
    final completer = Completer<Object?>();
    _pending[id] = completer;
    final message = JSObject();
    message['id'] = id.toJS;
    message['op'] = op.toJS;
    message['args'] = args;
    _worker.callMethod<JSAny?>('postMessage'.toJS, message, transfer.toJS);
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
}
