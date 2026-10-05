@TestOn('browser')
@Timeout(Duration(minutes: 20))
library;

import 'package:cipherbird_benchmark/cipherbird_benchmark.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

void main() {
  test('browser throughput table', () async {
    await CipherBird.preload();
    final table = await runSuite(
      CipherBird.instance,
      label: 'cipherbird (WebAssembly)',
      log: print,
    );
    print('RESULTS_BEGIN\n${table.render()}RESULTS_END');
  });
}
