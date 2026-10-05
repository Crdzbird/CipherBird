import 'dart:io';

import 'package:cipherbird_benchmark/cipherbird_benchmark.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';

Future<void> main() async {
  await CipherBird.preload();
  final table = await runSuite(
    CipherBird.instance,
    label: 'cipherbird (native)',
    log: stderr.writeln,
  );
  stdout.write(table.render());
}
