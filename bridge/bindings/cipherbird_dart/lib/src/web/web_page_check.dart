import 'package:cipherbird_dart/src/engine_integrity.dart';

/// What a Flutter web page has and lacks for the engine: the two boot
/// tags with current digests, a preload for the engine, and a Content
/// Security Policy that lets the worker spawn. Response headers cannot be
/// read from the page and are listed as things to check on the host.
final class WebPageCheck {
  const WebPageCheck();

  /// The plugin serves its assets under `assets/packages/cipherbird`, the
  /// Dart twin under `packages/cipherbird_dart`; both pages are checked.
  static const _assets = '(assets/)?packages/cipherbird(_dart)?/assets/';
  static final _engineTag = RegExp(
    '<script src="${_assets}cipherbird.js"[^>]*>',
  );
  static final _bootTag = RegExp(
    '<script src="${_assets}cipherbird_boot.js"[^>]*>',
  );
  static final _preload = RegExp(
    '<link[^>]*rel="preload"[^>]*cipherbird.wasm',
  );
  static final _csp = RegExp(
    '<meta[^>]*http-equiv="Content-Security-Policy"[^>]*content="([^"]*)"',
  );

  /// One line per finding; the first word is `ok`, `missing` or `note`.
  List<String> report(String html) {
    final lines = <String>[];
    final engine = _engineTag.firstMatch(html);
    lines.add(switch (engine) {
      null => 'missing engine tag: run dart run cipherbird:web_setup',
      _ when engine.group(0)!.contains(EngineIntegrity.engine) =>
        'ok engine tag with the current digest',
      _ => 'missing current digest on the engine tag: rerun web_setup',
    });
    final boot = _bootTag.firstMatch(html);
    lines.add(switch (boot) {
      null =>
        'note no boot tag: the app awaits CipherBird.preload (web_setup --boot drops it)',
      _ when boot.group(0)!.contains(EngineIntegrity.boot) =>
        'ok boot tag with the current digest',
      _ => 'missing current digest on the boot tag: rerun web_setup --boot',
    });
    lines.add(
      _preload.hasMatch(html)
          ? 'ok preload for cipherbird.wasm'
          : 'note no preload link for cipherbird.wasm; add one so the download starts with the page',
    );
    final csp = _csp.firstMatch(html)?.group(1);
    lines.add(switch (csp) {
      null =>
        'note no Content-Security-Policy meta tag; a host header may set one',
      _ when csp.contains('worker-src') && !csp.contains('blob:') =>
        'missing worker-src blob: in the Content-Security-Policy, the engine worker cannot spawn',
      _ when csp.contains('unsafe-eval') =>
        'note the Content-Security-Policy allows unsafe-eval, which the engine does not need',
      _ => 'ok Content-Security-Policy meta tag',
    });
    lines.add(
      'note check on the host: Brotli or gzip, an immutable cache header for '
      'cipherbird.wasm and cipherbird.js, and the isolation headers only when a '
      'threaded engine ships',
    );
    return lines;
  }

  /// True when no line starts with `missing`.
  bool passes(String html) =>
      report(html).every((l) => !l.startsWith('missing'));
}
