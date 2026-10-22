import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/checks/check_runner.dart';
import 'package:cipherbird_example/checks/checks_screen.dart';
import 'package:cipherbird_example/play/playground_index.dart';
import 'package:cipherbird_example/sections/envelopes_checks.dart';
import 'package:cipherbird_example/sections/hardware_checks.dart';
import 'package:cipherbird_example/sections/overview_checks.dart';
import 'package:cipherbird_example/sections/post_quantum_checks.dart';
import 'package:cipherbird_example/sections/primitives_checks.dart';
import 'package:cipherbird_example/sections/validated_module_checks.dart';
import 'package:flutter/material.dart';

/// The section switcher. The primitives section also runs once at startup
/// and prints CIPHERBIRD_SELFTEST for the scripted verifications.
final class ShowcaseHome extends StatefulWidget {
  const ShowcaseHome({super.key});

  @override
  State<ShowcaseHome> createState() => _ShowcaseHomeState();
}

final class _ShowcaseHomeState extends State<ShowcaseHome> {
  int _index = 0;

  @override
  void initState() {
    super.initState();
    _selfTest();
  }

  Future<void> _selfTest() async {
    final outcomes = await runChecks(
      PrimitivesChecks.build(CipherBird.instance),
    );
    final ok = outcomes.every((o) => o.passed);
    debugPrint('CIPHERBIRD_SELFTEST: ${ok ? 'OK' : 'FAILED'}');
  }

  @override
  Widget build(BuildContext context) {
    final lib = CipherBird.instance;
    final screens = [
      ChecksScreen(title: 'Overview', checks: OverviewChecks.build(lib)),
      ChecksScreen(title: 'Primitives', checks: PrimitivesChecks.build(lib)),
      ChecksScreen(title: 'Post-quantum', checks: PostQuantumChecks.build(lib)),
      ChecksScreen(title: 'Envelopes', checks: EnvelopesChecks.build(lib)),
      ChecksScreen(title: 'Hardware keys', checks: HardwareChecks.build(lib)),
      ChecksScreen(
        title: 'Validated module',
        checks: ValidatedModuleChecks.build(lib),
      ),
      const PlaygroundIndex(),
    ];
    return Scaffold(
      body: IndexedStack(index: _index, children: screens),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _index,
        onDestinationSelected: (i) => setState(() => _index = i),
        destinations: const [
          NavigationDestination(icon: Icon(Icons.info_outline), label: 'Info'),
          NavigationDestination(icon: Icon(Icons.lock_outline), label: 'Core'),
          NavigationDestination(
            icon: Icon(Icons.science_outlined),
            label: 'PQ',
          ),
          NavigationDestination(icon: Icon(Icons.mail_outline), label: 'Seal'),
          NavigationDestination(icon: Icon(Icons.memory), label: 'HW'),
          NavigationDestination(
            icon: Icon(Icons.verified_outlined),
            label: 'FIPS',
          ),
          NavigationDestination(
            icon: Icon(Icons.play_circle_outline),
            label: 'Play',
          ),
        ],
      ),
    );
  }
}
