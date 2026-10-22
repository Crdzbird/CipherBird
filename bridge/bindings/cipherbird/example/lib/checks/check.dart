/// One demonstrable fact about the library: [run] returns a short detail
/// when it holds, throws when it does not, and throws [SkipCheck] when the
/// platform cannot show it.
final class Check {
  const Check(this.label, this.run);

  /// What the check demonstrates.
  final String label;

  /// Produces a detail line or throws.
  final Future<String> Function() run;
}

/// Thrown by a check the current platform cannot perform.
final class SkipCheck implements Exception {
  const SkipCheck(this.reason);

  /// Why the platform cannot perform it.
  final String reason;
}
