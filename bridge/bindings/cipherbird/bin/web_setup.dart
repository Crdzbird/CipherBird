import 'dart:io';

const String _engineTag =
    '<script src="assets/packages/cipherbird/assets/cipherbird.js" defer></script>';
const String _bootTag =
    '<script src="assets/packages/cipherbird/assets/cipherbird_boot.js" defer></script>';
const String _bootstrapTag = '<script src="flutter_bootstrap.js"';

/// Adds the CipherBird engine scripts to the app's `web/index.html` so the
/// engine is instantiated while Flutter bootstraps and no await is needed
/// before the first use. Idempotent; `--remove` takes the tags out again.
///
///     dart run cipherbird:web_setup
void main(List<String> arguments) {
  final remove = arguments.contains('--remove');
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
  final updated = remove
      ? withoutEngineScripts(file.readAsStringSync())
      : withEngineScripts(file.readAsStringSync());
  if (updated == null) {
    stdout.writeln('cipherbird: $path already ${remove ? 'clean' : 'set up'}');
    return;
  }
  file.writeAsStringSync(updated);
  stdout.writeln(
    'cipherbird: ${remove ? 'removed the engine scripts from' : 'added the engine scripts to'} $path',
  );
}

/// The page with both tags inserted before the Flutter bootstrap script, or
/// before `</head>` when the page has no bootstrap tag; null when present.
String? withEngineScripts(String html) {
  if (html.contains(_bootTag)) {
    return null;
  }
  final without = withoutEngineScripts(html) ?? html;
  const insertion = '$_engineTag\n  $_bootTag\n  ';
  final bootstrap = without.indexOf(_bootstrapTag);
  if (bootstrap >= 0) {
    return without.replaceRange(bootstrap, bootstrap, insertion);
  }
  final head = without.indexOf('</head>');
  if (head >= 0) {
    return without.replaceRange(head, head, insertion);
  }
  return null;
}

/// The page with both tags removed, or null when neither is present.
String? withoutEngineScripts(String html) {
  final pattern = RegExp(
    r'[ \t]*<script src="assets/packages/cipherbird/assets/cipherbird(_boot)?\.js" defer></script>\n?',
  );
  if (!pattern.hasMatch(html)) {
    return null;
  }
  return html.replaceAll(pattern, '');
}
