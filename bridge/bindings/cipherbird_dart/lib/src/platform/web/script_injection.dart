part of 'web_platform.dart';

/// Appends a script tag for [url] whose bytes must match [integrity], the
/// Subresource Integrity digest the engine was built with, and completes
/// once the browser has run it. A digest mismatch is a load error.
Future<void> _injectScript(String url, String integrity) {
  final completer = Completer<void>();
  final document = globalContext.getProperty<JSObject>('document'.toJS);
  final script = document.callMethod<JSObject>(
    'createElement'.toJS,
    'script'.toJS,
  );
  script['src'] = url.toJS;
  script['integrity'] = integrity.toJS;
  script['crossOrigin'] = 'anonymous'.toJS;
  script['onload'] = (JSAny? event) {
    completer.complete();
  }.toJS;
  script['onerror'] = ((JSAny? event) {
    completer.completeError(
      StateError('cipherbird: failed to fetch or verify $url'),
    );
  }).toJS;
  document
      .getProperty<JSObject>('head'.toJS)
      .callMethod<JSAny?>('appendChild'.toJS, script);
  return completer.future;
}
