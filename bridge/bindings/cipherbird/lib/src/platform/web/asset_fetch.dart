part of 'web_platform.dart';

/// Fetches [url] and returns its bytes only when they match [integrity]; the
/// browser enforces the digest and rejects the response otherwise.
Future<JSArrayBuffer> _fetchVerified(String url, String integrity) async {
  final options = JSObject();
  options['integrity'] = integrity.toJS;
  final response = await globalContext
      .callMethod<JSPromise<JSObject>>('fetch'.toJS, url.toJS, options)
      .toDart;
  if (!response.getProperty<JSBoolean>('ok'.toJS).toDart) {
    throw StateError('cipherbird: failed to fetch $url');
  }
  return response
      .callMethod<JSPromise<JSArrayBuffer>>('arrayBuffer'.toJS)
      .toDart;
}

/// The verified bytes of [url] decoded as UTF-8.
Future<String> _fetchVerifiedText(String url, String integrity) async {
  final buffer = await _fetchVerified(url, integrity);
  return utf8.decode(buffer.toDart.asUint8List());
}
