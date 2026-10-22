/// How a check ended.
enum CheckStatus { passed, failed, skipped }

/// A check's label, status and detail line.
final class CheckOutcome {
  const CheckOutcome(this.label, this.status, this.detail);

  final String label;
  final CheckStatus status;
  final String detail;

  bool get passed => status != CheckStatus.failed;
}
