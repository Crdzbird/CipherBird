import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/playground.dart';
import 'package:cipherbird_example/play/playground_index.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Presses every button of every playground in order on the device, except
/// the file pickers, which need a hand, and
/// fails if an action raised anything other than the refusals the
/// playground exists to show:
/// `flutter test integration_test/playground_test.dart -d <device id>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  setUpAll(CipherBird.preload);

  const refusalButtons = {
    'Open as Carol',
    'Replay last',
    'Handshake as Mallory',
    'Reveal with the wrong key',
  };

  testWidgets('every playground action runs', (_) async {
    var unexpected = 0;
    for (final Playground p in PlaygroundIndex.all(CipherBird.instance)) {
      for (final a in p.actions) {
        if (a.label.startsWith('Pick a file')) {
          continue;
        }
        await a.run();
        final line = p.log.isEmpty ? '' : p.log.first;
        final raised = RegExp('(Exception|Error)').hasMatch(line);
        final tolerated =
            refusalButtons.contains(a.label) || line.contains('unsupported');
        if (raised && !tolerated) {
          unexpected++;
        }
        debugPrint('play ${p.title} / ${a.label}: $line');
      }
    }
    expect(unexpected, 0);
  });
}
