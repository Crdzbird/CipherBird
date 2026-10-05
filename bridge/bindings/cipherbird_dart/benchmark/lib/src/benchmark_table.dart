import 'package:cipherbird_benchmark/src/timing.dart';

/// Collects comparison rows and renders them as a Markdown table.
final class BenchmarkTable {
  /// Creates a table whose first column names the reference implementation.
  BenchmarkTable(this.columns, {required this.log});

  /// Column headers after the operation name; the first is the reference.
  final List<String> columns;

  /// Receives each finished row as it completes.
  final void Function(String line) log;

  final List<List<String>> _rows = [];

  /// Times every implementation of one operation. A null implementation
  /// renders as `n/a`; [size] switches the unit to MB/s.
  Future<void> row(
    String name,
    List<Future<void> Function()?> implementations, {
    int? size,
  }) async {
    final cells = <String>[name];
    double? reference;
    for (final implementation in implementations) {
      if (implementation == null) {
        cells.add('n/a');
        continue;
      }
      try {
        final value = await opsPerSecond(implementation);
        reference ??= value;
        final text = size == null
            ? operationsPerSecond(value)
            : megabytesPerSecond(value, size);
        cells.add(
          cells.length == 1 ? text : '$text (${compare(reference, value)})',
        );
      } on Object catch (error) {
        cells.add('error: ${error.runtimeType}');
      }
    }
    _rows.add(cells);
    log(cells.join(' | '));
  }

  /// How [value] relates to the [reference] figure.
  static String compare(double reference, double value) => value < reference
      ? '${(reference / value).toStringAsFixed(1)}x slower'
      : '${(value / reference).toStringAsFixed(1)}x faster';

  /// The Markdown rendering of every row so far.
  String render() {
    final out = StringBuffer()
      ..writeln('| Operation | ${columns.join(' | ')} |')
      ..writeln('|---|${'---|' * columns.length}');
    for (final cells in _rows) {
      out.writeln('| ${cells.join(' | ')} |');
    }
    return out.toString();
  }
}
