import 'dart:convert';
import 'dart:io';

import 'package:cipherbird_benchmark/cipherbird_benchmark.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';

/// Prints the comparison table. `--emit-json <file>` also stores the
/// reference figures (operations per second by row) so a later run can
/// compare against them with `--previous <file> --previous-label <name>`;
/// without `--previous` the published 1.1.0 figures are used. `--no-bank`
/// skips the 1.2.0 rows, for measuring an engine that predates them.
Future<void> main(List<String> args) async {
  String? option(String name) {
    final i = args.indexOf(name);
    return i >= 0 && i + 1 < args.length ? args[i + 1] : null;
  }

  await CipherBird.preload();
  final previousPath = option('--previous');
  final previous = previousPath == null
      ? previousNative
      : (jsonDecode(File(previousPath).readAsStringSync())
                as Map<String, Object?>)
            .map((k, v) => MapEntry(k, (v! as num).toDouble()));
  final table = await runSuite(
    CipherBird.instance,
    label: 'cipherbird (native)',
    log: stderr.writeln,
    previous: previous,
    previousLabel: option('--previous-label') ?? '1.1.0',
    bank: !args.contains('--no-bank'),
  );
  stdout.write(table.render());
  stdout.write('\n');
  stdout.write(renderTimeSummary(table));
  final emit = option('--emit-json');
  if (emit != null) {
    File(emit).writeAsStringSync(jsonEncode(table.referenceFigures));
  }
}
