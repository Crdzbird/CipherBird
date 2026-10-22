import 'package:cipherbird_example/checks/check_outcome.dart';
import 'package:flutter/material.dart';

/// One outcome row: status icon, label, detail.
final class OutcomeTile extends StatelessWidget {
  const OutcomeTile(this.outcome, {super.key});

  final CheckOutcome outcome;

  @override
  Widget build(BuildContext context) => ListTile(
    leading: Icon(_icon, color: _color),
    title: Text(outcome.label),
    subtitle: Text(outcome.detail, style: const TextStyle(fontSize: 12)),
  );

  IconData get _icon => switch (outcome.status) {
    CheckStatus.passed => Icons.check_circle_outline,
    CheckStatus.failed => Icons.error_outline,
    CheckStatus.skipped => Icons.remove_circle_outline,
  };

  Color get _color => switch (outcome.status) {
    CheckStatus.passed => Colors.green,
    CheckStatus.failed => Colors.red,
    CheckStatus.skipped => Colors.grey,
  };
}
