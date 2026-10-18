@TestOn('vm')
library;

import 'dart:io';

import 'package:test/test.dart';

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
      '<script src="packages/cipherbird_dart/assets/cipherbird.js" defer></script>\n'
          '  <script src="packages/cipherbird_dart/assets/cipherbird_boot.js" defer></script>\n'
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
}
