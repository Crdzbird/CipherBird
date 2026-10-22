import 'package:cipherbird_benchmark/src/benchmark_table.dart';
import 'package:cipherbird_benchmark/src/timing.dart';

/// A second table that answers the time question directly: for each
/// operation, how long cipherbird takes, how long the fastest alternative
/// takes, and the difference per operation.
String renderTimeSummary(BenchmarkTable table) {
  final others = table.columns.skip(1).toList();
  final out = StringBuffer()
    ..writeln(
      '| Operation | ${table.columns.first} | fastest alternative | time per operation | difference |',
    )
    ..writeln('|---|---|---|---|---|');
  for (final (name, rates) in table.measurements) {
    final mine = rates.isEmpty ? null : rates.first;
    if (mine == null) {
      continue;
    }
    var bestRate = 0.0;
    String? best;
    for (var i = 1; i < rates.length; i++) {
      final r = rates[i];
      if (r != null && r > bestRate) {
        bestRate = r;
        best = others[i - 1];
      }
    }
    if (best == null) {
      out.writeln('| $name | ${timePerOperation(mine)} | none | | |');
      continue;
    }
    out.writeln(
      '| $name | ${timePerOperation(mine)} | $best | ${timePerOperation(bestRate)} | ${timeDifference(mine, bestRate)} |',
    );
  }
  return out.toString();
}
