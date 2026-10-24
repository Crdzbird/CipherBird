import 'dart:js_interop';
import 'dart:typed_data';

import 'package:cipherbird/src/hardware/fips/web/subtle.dart';

/// Key import, generation and export on `crypto.subtle`.
final class SubtleKeys {
  const SubtleKeys(this._subtle);

  final Subtle _subtle;

  Future<JSObject> importRaw(
    Uint8List keyData,
    Map<String, Object?> algorithm,
    List<String> usages, {
    String format = 'raw',
  }) async {
    final r = await _subtle.invoke('importKey', [
      format.toJS,
      keyData.toJS,
      _subtle.alg(algorithm),
      false.toJS,
      usages.map((u) => u.toJS).toList().toJS,
    ]);
    return r! as JSObject;
  }

  Future<JSObject> generate(
    Map<String, Object?> algorithm,
    List<String> usages,
  ) async {
    final r = await _subtle.invoke('generateKey', [
      _subtle.alg(algorithm),
      true.toJS,
      usages.map((u) => u.toJS).toList().toJS,
    ]);
    return r! as JSObject;
  }

  Future<Uint8List> exportRaw(JSObject key) =>
      _subtle.bytes('exportKey', ['raw'.toJS, key]);

  Future<Map<String, Object?>> exportJwk(JSObject key) async {
    final r = await _subtle.invoke('exportKey', ['jwk'.toJS, key]);
    return (r.dartify()! as Map<Object?, Object?>).cast<String, Object?>();
  }
}
