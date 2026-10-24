import 'dart:io';

import 'package:cipherbird_dart/src/engine_integrity.dart';
import 'package:cipherbird_dart/src/web/web_page_check.dart';

const String _engineTag =
    '<script src="packages/cipherbird_dart/assets/cipherbird.js" '
    'integrity="${EngineIntegrity.engine}" crossorigin="anonymous" defer></script>';
const String _bootTag =
    '<script src="packages/cipherbird_dart/assets/cipherbird_boot.js" '
    'integrity="${EngineIntegrity.boot}" crossorigin="anonymous" defer></script>';
const String _bootstrapTag = '<script src="flutter_bootstrap.js"';

/// Adds the CipherBird engine script to the app's `web/index.html` with the
/// integrity digest of the bundled file, so the download starts while
/// Flutter bootstraps and the browser refuses a changed file. With `--boot`
/// the page also instantiates the engine (`cipherbird_boot.js`); build the
/// app with `--dart-define=CIPHERBIRD_PAGE_ENGINE=true` to adopt it and drop
/// the await. Idempotent: rerun after upgrading the package to refresh the
/// digests; `--remove` takes the tags out again.
///
///     dart run cipherbird_dart:web_setup
///     dart run cipherbird_dart:web_setup --boot
///     dart run cipherbird_dart:web_setup --check
void main(List<String> arguments) {
  final remove = arguments.contains('--remove');
  final check = arguments.contains('--check');
  final boot = arguments.contains('--boot');
  final path = arguments.firstWhere(
    (a) => !a.startsWith('--'),
    orElse: () => 'web/index.html',
  );
  final file = File(path);
  if (!file.existsSync()) {
    stderr.writeln(
      'cipherbird: $path not found; run this from the app root '
      'of a Flutter project with web support',
    );
    exitCode = 2;
    return;
  }
  if (check) {
    final report = const WebPageCheck().report(file.readAsStringSync());
    report.forEach(stdout.writeln);
    exitCode = report.any((String l) => l.startsWith('missing')) ? 1 : 0;
    return;
  }
  final updated = remove
      ? withoutEngineScripts(file.readAsStringSync())
      : withEngineScripts(file.readAsStringSync(), boot: boot);
  if (updated == null) {
    stdout.writeln('cipherbird: $path already ${remove ? 'clean' : 'set up'}');
    return;
  }
  file.writeAsStringSync(updated);
  stdout.writeln(
    'cipherbird: ${remove ? 'removed the engine scripts from' : 'added the engine scripts to'} $path',
  );
}

/// The page with the engine tag, and with [boot] the boot tag, inserted
/// before the Flutter bootstrap script, or before `</head>` when the page
/// has no bootstrap tag; null when the page already has exactly those tags
/// or has nowhere to put them. Tags from an earlier version are replaced.
String? withEngineScripts(String html, {required bool boot}) {
  final insertion = boot ? '$_engineTag\n  $_bootTag\n  ' : '$_engineTag\n  ';
  final rebuilt = _insert(withoutEngineScripts(html) ?? html, insertion);
  if (rebuilt == null || rebuilt == html) {
    return null;
  }
  return rebuilt;
}

String? _insert(String html, String insertion) {
  final bootstrap = html.indexOf(_bootstrapTag);
  if (bootstrap >= 0) {
    return html.replaceRange(bootstrap, bootstrap, insertion);
  }
  final head = html.indexOf('</head>');
  if (head >= 0) {
    return html.replaceRange(head, head, insertion);
  }
  return null;
}

/// The page with both tags removed, whatever digests they carry, or null
/// when neither is present.
String? withoutEngineScripts(String html) {
  final pattern = RegExp(
    r'[ \t]*<script src="packages/cipherbird_dart/assets/cipherbird(_boot)?\.js"[^>]*></script>\n?',
  );
  if (!pattern.hasMatch(html)) {
    return null;
  }
  return html.replaceAll(pattern, '');
}
