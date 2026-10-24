import 'dart:async';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';

/// A small object store in the origin's IndexedDB for WebCrypto key
/// objects: a non-extractable key survives there without its bytes ever
/// being readable by script.
final class IndexedDbKeys {
  const IndexedDbKeys();

  static const _db = 'cipherbird';
  static const _store = 'keys';

  Future<JSObject> _open() {
    final request = globalContext
        .getProperty<JSObject>('indexedDB'.toJS)
        .callMethod<JSObject>('open'.toJS, _db.toJS, 1.toJS);
    request['onupgradeneeded'] = ((JSObject _) {
      request
          .getProperty<JSObject>('result'.toJS)
          .callMethod<JSAny?>('createObjectStore'.toJS, _store.toJS);
    }).toJS;
    return _await(request).then((r) => r! as JSObject);
  }

  Future<JSAny?> _run(String mode, JSObject Function(JSObject store) op) async {
    final db = await _open();
    try {
      final store = db
          .callMethod<JSObject>('transaction'.toJS, _store.toJS, mode.toJS)
          .callMethod<JSObject>('objectStore'.toJS, _store.toJS);
      return await _await(op(store));
    } finally {
      db.callMethod<JSAny?>('close'.toJS);
    }
  }

  Future<void> put(String label, JSAny value) =>
      _run('readwrite', (s) => s.callMethod('put'.toJS, value, label.toJS));

  Future<JSAny?> get(String label) =>
      _run('readonly', (s) => s.callMethod('get'.toJS, label.toJS));

  Future<void> delete(String label) =>
      _run('readwrite', (s) => s.callMethod('delete'.toJS, label.toJS));

  /// Completes with an IndexedDB request's result, or its error.
  static Future<JSAny?> _await(JSObject request) {
    final done = Completer<JSAny?>();
    request['onsuccess'] = ((JSObject _) {
      done.complete(request.getProperty<JSAny?>('result'.toJS));
    }).toJS;
    request['onerror'] = ((JSObject _) {
      final error = request.getProperty<JSObject?>('error'.toJS);
      final message = error?.getProperty<JSString?>('message'.toJS)?.toDart;
      done.completeError(
        StateError('IndexedDB: ${message ?? 'request failed'}'),
      );
    }).toJS;
    return done.future;
  }
}
