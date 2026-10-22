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

/// The mean time one operation took, from its rate.
String timePerOperation(double ops) {
  final micros = 1e6 / ops;
  if (micros < 1000) {
    return '${micros.toStringAsFixed(micros < 10 ? 2 : 1)} us';
  }
  if (micros < 1e6) {
    return '${(micros / 1000).toStringAsFixed(micros < 1e4 ? 2 : 1)} ms';
  }
  return '${(micros / 1e6).toStringAsFixed(2)} s';
}

/// The change of [value] against [previous] as a signed percentage.
String changeSince(double previous, double value) {
  final pct = (value / previous - 1) * 100;
  final sign = pct >= 0 ? '+' : '';
  return '$sign${pct.toStringAsFixed(0)}%';
}

/// How much longer or shorter one operation takes at [value] than at the
/// [reference] rate, signed from the reference's point of view.
String timeDifference(double reference, double value) {
  final micros = 1e6 / value - 1e6 / reference;
  final sign = micros >= 0 ? '+' : '-';
  return '$sign${timePerOperation(1e6 / micros.abs())}';
}

/// How [value] relates to the [reference] rate: factor and time difference.
String compareRates(double reference, double value) {
  final factor = value < reference
      ? '${(reference / value).toStringAsFixed(1)}x slower'
      : '${(value / reference).toStringAsFixed(1)}x faster';
  return '$factor, ${timeDifference(reference, value)}';
}
