part of 'web_platform.dart';

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
