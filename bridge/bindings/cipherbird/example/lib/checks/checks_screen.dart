import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/checks/check_outcome.dart';
import 'package:cipherbird_example/checks/check_runner.dart';
import 'package:cipherbird_example/checks/outcome_tile.dart';
import 'package:flutter/material.dart';

/// Runs a section's checks when first shown and lists their outcomes.
final class ChecksScreen extends StatefulWidget {
  const ChecksScreen({required this.title, required this.checks, super.key});

  final String title;
  final List<Check> checks;

  @override
  State<ChecksScreen> createState() => _ChecksScreenState();
}

final class _ChecksScreenState extends State<ChecksScreen> {
  late Future<List<CheckOutcome>> _outcomes = runChecks(widget.checks);

  void _rerun() => setState(() => _outcomes = runChecks(widget.checks));

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(
      title: Text(widget.title),
      actions: [IconButton(onPressed: _rerun, icon: const Icon(Icons.refresh))],
    ),
    body: FutureBuilder<List<CheckOutcome>>(
      future: _outcomes,
      builder: (context, snap) {
        final data = snap.data;
        if (data == null) {
          return const Center(child: CircularProgressIndicator());
        }
        final failed = data.where((o) => !o.passed).length;
        return ListView(
          children: [
            ListTile(
              title: Text(
                failed == 0
                    ? 'All ${data.length} checks hold'
                    : '$failed failed',
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ),
            for (final o in data) OutcomeTile(o),
          ],
        );
      },
    ),
  );
}
