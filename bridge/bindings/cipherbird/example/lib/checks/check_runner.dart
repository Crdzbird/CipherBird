import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/checks/check_outcome.dart';

/// Runs [checks] in order; a throw fails the check, a [SkipCheck] skips it.
Future<List<CheckOutcome>> runChecks(List<Check> checks) async {
  final out = <CheckOutcome>[];
  for (final c in checks) {
    out.add(await runOne(c));
  }
  return out;
}

Future<CheckOutcome> runOne(Check c) async {
  try {
    return CheckOutcome(c.label, CheckStatus.passed, await c.run());
  } on SkipCheck catch (e) {
    return CheckOutcome(c.label, CheckStatus.skipped, e.reason);
  } on Object catch (e) {
    return CheckOutcome(c.label, CheckStatus.failed, '$e');
  }
}
