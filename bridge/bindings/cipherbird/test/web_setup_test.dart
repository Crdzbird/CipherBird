@TestOn('vm')
library;

import 'dart:io';

import 'package:cipherbird/src/engine_integrity.dart';
import 'package:cipherbird/src/web/web_page_check.dart';
import 'package:flutter_test/flutter_test.dart';

const _page = '''
<!DOCTYPE html>
<html>
<head>
  <title>app</title>
  <script src="flutter_bootstrap.js" async></script>
</head>
<body></body>
</html>
''';

Future<ProcessResult> _run(List<String> args, Directory dir) => Process.run(
  'dart',
  ['run', '${Directory.current.path}/bin/web_setup.dart', ...args],
  workingDirectory: dir.path,
);

void main() {
  late Directory dir;
  setUp(() {
    dir = Directory.systemTemp.createTempSync('cipherbird_web_setup_');
    Directory('${dir.path}/web').createSync();
    File('${dir.path}/web/index.html').writeAsStringSync(_page);
  });
  tearDown(() => dir.deleteSync(recursive: true));

  test('adds the engine script before the bootstrap tag, once', () async {
    final first = await _run(const [], dir);
    expect(first.exitCode, 0, reason: first.stderr.toString());
    final html = File('${dir.path}/web/index.html').readAsStringSync();
    final engine = html.indexOf('assets/cipherbird.js');
    final bootstrap = html.indexOf('flutter_bootstrap.js');
    expect(engine, greaterThan(0));
    expect(bootstrap, greaterThan(engine));
    expect(html, isNot(contains('cipherbird_boot.js')));
    expect('integrity="sha384-'.allMatches(html).length, 1);
    expect('crossorigin="anonymous"'.allMatches(html).length, 1);
    final second = await _run(const [], dir);
    expect(second.stdout.toString(), contains('already set up'));
    expect(File('${dir.path}/web/index.html').readAsStringSync(), html);
  });

  test('--boot adds the boot script after the engine script', () async {
    final result = await _run(const ['--boot'], dir);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    final html = File('${dir.path}/web/index.html').readAsStringSync();
    final engine = html.indexOf('assets/cipherbird.js');
    final boot = html.indexOf('cipherbird_boot.js');
    expect(boot, greaterThan(engine));
    expect(html.indexOf('flutter_bootstrap.js'), greaterThan(boot));
    expect('integrity="sha384-'.allMatches(html).length, 2);
    final plain = await _run(const [], dir);
    expect(plain.exitCode, 0);
    final back = File('${dir.path}/web/index.html').readAsStringSync();
    expect(back, isNot(contains('cipherbird_boot.js')));
  });

  test('--remove restores the original page', () async {
    await _run(const ['--boot'], dir);
    final removed = await _run(const ['--remove'], dir);
    expect(removed.exitCode, 0, reason: removed.stderr.toString());
    expect(File('${dir.path}/web/index.html').readAsStringSync(), _page);
  });

  test('tags from an earlier version are replaced with digest tags', () async {
    final old = _page.replaceFirst(
      '<script src="flutter_bootstrap.js"',
      '<script src="assets/packages/cipherbird/assets/cipherbird.js" defer></script>\n'
          '  <script src="assets/packages/cipherbird/assets/cipherbird_boot.js" defer></script>\n'
          '  <script src="flutter_bootstrap.js"',
    );
    File('${dir.path}/web/index.html').writeAsStringSync(old);
    final result = await _run(const [], dir);
    expect(result.exitCode, 0, reason: result.stderr.toString());
    final html = File('${dir.path}/web/index.html').readAsStringSync();
    expect('cipherbird.js"'.allMatches(html).length, 1);
    expect(html, isNot(contains('cipherbird_boot.js')));
    expect('integrity="sha384-'.allMatches(html).length, 1);
  });

  test('a missing page is reported', () async {
    final result = await _run(const ['web/missing.html'], dir);
    expect(result.exitCode, 2);
  });

  group('WebPageCheck', () {
    const check = WebPageCheck();
    test('reports a bare page as missing the engine tag', () {
      final lines = check.report('<html><head></head><body></body></html>');
      expect(lines.first, startsWith('missing engine tag'));
      expect(check.passes('<html></html>'), isFalse);
    });
    test('passes a page web_setup produced and flags a bad policy', () {
      const page =
          '<html><head> '
          '<script src="assets/packages/cipherbird/assets/cipherbird.js" '
          'integrity="${EngineIntegrity.engine}" crossorigin="anonymous" defer></script> '
          '<script src="assets/packages/cipherbird/assets/cipherbird_boot.js" '
          'integrity="${EngineIntegrity.boot}" crossorigin="anonymous" defer></script> '
          '<script src="flutter_bootstrap.js" async></script></head></html>';
      expect(check.passes(page), isTrue);
      expect(check.report(page).where((l) => l.startsWith('ok')).length, 2);
      final strict = page.replaceFirst(
        '<head>',
        '<head><meta http-equiv="Content-Security-Policy" content="worker-src none">',
      );
      expect(check.passes(strict), isFalse);
    });
  });
}
