import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/checks/check_outcome.dart';
import 'package:cipherbird_example/checks/check_runner.dart';
import 'package:cipherbird_example/sections/envelopes_checks.dart';
import 'package:cipherbird_example/sections/hardware_checks.dart';
import 'package:cipherbird_example/sections/overview_checks.dart';
import 'package:cipherbird_example/sections/post_quantum_checks.dart';
import 'package:cipherbird_example/sections/primitives_checks.dart';
import 'package:cipherbird_example/sections/validated_module_checks.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Runs every showcase section on the device and fails on any failed
/// check; skipped checks are reported, not failed:
/// `flutter test integration_test/showcase_test.dart -d <device id>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(CipherBird.preload);

  Map<String, List<Check>> sections() {
    final lib = CipherBird.instance;
    return {
      'overview': OverviewChecks.build(lib),
      'primitives': PrimitivesChecks.build(lib),
      'post-quantum': PostQuantumChecks.build(lib),
      'envelopes': EnvelopesChecks.build(lib),
      'hardware': HardwareChecks.build(lib),
      'validated module': ValidatedModuleChecks.build(lib),
    };
  }

  testWidgets('every showcase section holds on this device', (_) async {
    var failed = 0;
    for (final entry in sections().entries) {
      final outcomes = await runChecks(entry.value);
      for (final o in outcomes) {
        debugPrint(
          'showcase ${entry.key}: ${o.status.name} ${o.label}: ${o.detail}',
        );
        if (o.status == CheckStatus.failed) {
          failed++;
        }
      }
    }
    expect(failed, 0);
  });
}
