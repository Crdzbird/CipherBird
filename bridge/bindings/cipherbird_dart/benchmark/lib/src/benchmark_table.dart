import 'package:cipherbird_benchmark/src/timing.dart';

/// Collects comparison rows and renders them as Markdown. Every cell
/// carries the rate and the mean time of one operation; comparison cells
/// add the factor and the time difference against the reference, and the
/// reference cell the change against the previous release when known.
final class BenchmarkTable {
  /// Creates a table whose first column names the reference implementation.
  BenchmarkTable(
    this.columns, {
    required this.log,
    this.previous = const {},
    this.previousLabel = 'previous',
  });

  /// Column headers after the operation name; the first is the reference.
  final List<String> columns;

  /// Receives each finished row as it completes.
  final void Function(String line) log;

  /// Reference figures (operations per second) from the previous release.
  final Map<String, double> previous;

  /// How the previous release is named in the change column.
  final String previousLabel;

  final List<List<String>> _rows = [];
  final List<List<double?>> _rates = [];
  final List<String> _names = [];

  /// The reference column's operations per second by row name.
  final Map<String, double> referenceFigures = {};

  /// Times every implementation of one operation. A null implementation
  /// renders as `n/a`; [size] switches the unit to MB/s.
  Future<void> row(
    String name,
    List<Future<void> Function()?> implementations, {
    int? size,
  }) async {
    final cells = <String>[name];
    final rates = <double?>[];
    double? reference;
    for (final implementation in implementations) {
      if (implementation == null) {
        cells.add('n/a');
        rates.add(null);
        continue;
      }
      try {
        final value = await opsPerSecond(implementation);
        rates.add(value);
        final text =
            '${size == null ? operationsPerSecond(value) : megabytesPerSecond(value, size)}, ${timePerOperation(value)}';
        if (reference == null) {
          reference = value;
          referenceFigures[name] = value;
          cells.add(text);
          continue;
        }
        cells.add('$text (${compareRates(reference, value)})');
      } on Object catch (error) {
        cells.add('error: ${error.runtimeType}');
        rates.add(null);
      }
    }
    cells.insert(2, _change(name, reference));
    _rows.add(cells);
    _rates.add(rates);
    _names.add(name);
    log(cells.join(' | '));
  }

  String _change(String name, double? reference) {
    final before = previous[name];
    return before == null || reference == null
        ? 'new'
        : changeSince(before, reference);
  }

  /// The Markdown rendering of every row so far.
  String render() {
    final headers = [columns.first, 'vs $previousLabel', ...columns.skip(1)];
    final out = StringBuffer()
      ..writeln('| Operation | ${headers.join(' | ')} |')
      ..writeln('|---|${'---|' * headers.length}');
    for (final cells in _rows) {
      out.writeln('| ${cells.join(' | ')} |');
    }
    return out.toString();
  }

  /// Rates by row for the time summary.
  List<(String, List<double?>)> get measurements => [
    for (var i = 0; i < _names.length; i++) (_names[i], _rates[i]),
  ];
}
