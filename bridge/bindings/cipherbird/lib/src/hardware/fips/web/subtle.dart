import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/web/js_value.dart';

/// The browser's `crypto.subtle`, reached through plain interop so the
/// plugin needs no extra package. Every call returns a promise.
final class Subtle {
  const Subtle();

  JSObject get _crypto => globalContext.getProperty<JSObject>('crypto'.toJS);

  /// Calls [method] on `crypto.subtle` and awaits its promise.
  Future<JSAny?> invoke(String method, List<JSAny?> args) => _crypto
      .getProperty<JSObject>('subtle'.toJS)
      .callMethodVarArgs<JSPromise<JSAny?>>(method.toJS, args)
      .toDart;

  /// The promise's value as bytes.
  Future<Uint8List> bytes(String method, List<JSAny?> args) async =>
      ((await invoke(method, args))! as JSArrayBuffer).toDart.asUint8List();

  /// An algorithm dictionary: bytes become typed arrays, [JsValue] passes
  /// through, anything else is converted.
  JSAny alg(Map<String, Object?> m) {
    final o = JSObject();
    for (final e in m.entries) {
      o[e.key] = switch (e.value) {
        final Uint8List b => b.toJS,
        final JsValue j => j.value,
        final Object? v => v.jsify(),
      };
    }
    return o;
  }

  Future<Uint8List> digest(String hash, Uint8List data) => bytes('digest', [
    alg({'name': hash}),
    data.toJS,
  ]);

  Future<Uint8List> sign(Map<String, Object?> a, JSObject key, Uint8List d) =>
      bytes('sign', [alg(a), key, d.toJS]);

  Future<bool> verify(
    Map<String, Object?> a,
    JSObject key,
    Uint8List signature,
    Uint8List data,
  ) async {
    final r = await invoke('verify', [alg(a), key, signature.toJS, data.toJS]);
    return (r! as JSBoolean).toDart;
  }

  Future<Uint8List> encrypt(
    Map<String, Object?> a,
    JSObject key,
    Uint8List d,
  ) => bytes('encrypt', [alg(a), key, d.toJS]);

  Future<Uint8List> decrypt(
    Map<String, Object?> a,
    JSObject key,
    Uint8List d,
  ) => bytes('decrypt', [alg(a), key, d.toJS]);

  Future<Uint8List> deriveBits(
    Map<String, Object?> a,
    JSObject key,
    int bits,
  ) => bytes('deriveBits', [alg(a), key, bits.toJS]);

  /// [count] random bytes from `crypto.getRandomValues`, 64 KiB a call.
  Uint8List random(int count) {
    final out = Uint8List(count);
    for (var at = 0; at < count; at += 65536) {
      final end = at + 65536 > count ? count : at + 65536;
      _crypto.callMethod<JSAny?>(
        'getRandomValues'.toJS,
        Uint8List.sublistView(out, at, end).toJS,
      );
    }
    return out;
  }
}
