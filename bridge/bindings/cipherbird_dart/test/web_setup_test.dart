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

  test('adds both engine scripts before the bootstrap tag, once', () async {
    final first = await _run(const [], dir);
    expect(first.exitCode, 0, reason: first.stderr.toString());
    final html = File('${dir.path}/web/index.html').readAsStringSync();
    final engine = html.indexOf('assets/cipherbird.js');
    final boot = html.indexOf('cipherbird_boot.js');
    final bootstrap = html.indexOf('flutter_bootstrap.js');
    expect(engine, greaterThan(0));
    expect(boot, greaterThan(engine));
    expect(bootstrap, greaterThan(boot));
    final second = await _run(const [], dir);
    expect(second.stdout.toString(), contains('already set up'));
    expect(File('${dir.path}/web/index.html').readAsStringSync(), html);
  });

  test('--remove restores the original page', () async {
    await _run(const [], dir);
    final removed = await _run(const ['--remove'], dir);
    expect(removed.exitCode, 0, reason: removed.stderr.toString());
    expect(File('${dir.path}/web/index.html').readAsStringSync(), _page);
  });

  test('a missing page is reported', () async {
    final result = await _run(const ['web/missing.html'], dir);
    expect(result.exitCode, 2);
  });
}
