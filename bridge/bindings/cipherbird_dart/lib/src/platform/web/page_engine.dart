part of 'web_platform.dart';

/// Whether an engine the page instantiated through `cipherbird_boot.js` is
/// adopted from the `self.cipherbirdEngine` global. Off by default: the
/// global is set by whatever script runs on the page, so adopting it trusts
/// the page. Build with `--dart-define=CIPHERBIRD_PAGE_ENGINE=true` after
/// `dart run cipherbird:web_setup --boot` to drop the await on the web.
const bool adoptsPageEngine = bool.fromEnvironment('CIPHERBIRD_PAGE_ENGINE');

/// Adopts an engine the page instantiated through `cipherbird_boot.js`,
/// published as `self.cipherbirdEngine = {module, base}`. Returns true when
/// the engine is now loaded, so no asynchronous step is needed.
bool adoptPageEngine() {
  if (WebEngine.isLoaded) {
    return true;
  }
  if (!adoptsPageEngine) {
    return false;
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

/// Waits for a page boot still in flight (`self.cipherbirdEnginePromise`)
/// and adopts its result. False when the page is not booting the engine.
Future<bool> awaitPageEngine() async {
  if (!adoptsPageEngine) {
    return false;
  }
  final booting = globalContext.getProperty<JSPromise<JSObject>?>(
    'cipherbirdEnginePromise'.toJS,
  );
  if (booting == null) {
    return false;
  }
  await booting.toDart;
  return adoptPageEngine();
}
