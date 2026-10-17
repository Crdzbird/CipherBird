part of 'web_platform.dart';

/// Adopts an engine the page instantiated through `cipherbird_boot.js`,
/// published as `self.cipherbirdEngine = {module, base}`. Returns true when
/// the engine is now loaded, so no asynchronous step is needed.
bool adoptPageEngine() {
  if (WebEngine.isLoaded) {
    return true;
  }
  final booted = globalContext.getProperty<JSObject?>('cipherbirdEngine'.toJS);
  if (booted == null) {
    return false;
  }
  final module = booted.getProperty<JSObject>('module'.toJS);
  final base = booted.getProperty<JSString>('base'.toJS).toDart;
  WebEngine._current = WebEngine._(EngineModule._(module), base);
  return true;
}
