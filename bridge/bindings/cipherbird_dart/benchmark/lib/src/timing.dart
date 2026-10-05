/// Measures how many times [op] completes per second within [budget].
Future<double> opsPerSecond(
  Future<void> Function() op, {
  Duration budget = const Duration(seconds: 2),
}) async {
  await op();
  final stopwatch = Stopwatch()..start();
  var runs = 0;
  while (stopwatch.elapsed < budget) {
    await op();
    runs++;
  }
  return runs / (stopwatch.elapsedMicroseconds / 1e6);
}

/// Formats a throughput figure for a payload of [size] bytes.
String megabytesPerSecond(double ops, int size) =>
    '${(ops * size / (1 << 20)).toStringAsFixed(0)} MB/s';

/// Formats an operations-per-second figure.
String operationsPerSecond(double value) => value >= 100
    ? '${value.toStringAsFixed(0)} ops/s'
    : '${value.toStringAsFixed(1)} ops/s';
