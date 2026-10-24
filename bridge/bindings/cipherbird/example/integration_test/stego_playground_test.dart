import 'package:cipherbird/cipherbird.dart';

import 'support/play_driver.dart';

import 'package:cipherbird_example/play/stego_playground.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Hides and reveals through every mode of the steganography playground on
/// a device and checks what the log says:
/// `flutter test integration_test/stego_playground_test.dart -d <device id>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(CipherBird.preload);

  const secret = 'meet at the old bridge, bring the ledger';
  const modes = [
    'plain',
    'keyed placement',
    'encrypted',
    'physical seal (a photo is the key)',
    'HPKE to Bob',
    'image factor (OPRF secret + reference photo)',
    'recipe (custom pipeline)',
  ];

  testWidgets('every mode hides and reveals on a photo and on a sound', (
    _,
  ) async {
    for (final carrier in ['photo 512x512 PPM', 'tone 10 s WAV']) {
      final d = PlayDriver(StegoPlayground(CipherBird.instance));
      d.pick('Carrier', carrier);
      await d.expectLine('New carrier', 'room for');
      for (final mode in modes) {
        d.pick('Mode', mode);
        await d.expectLine('Hide', 'carrier bytes changed');
        await d.expectLine('Reveal', secret);
        await d.expectLine(
          'Reveal with the wrong key',
          mode == 'plain' ? secret : 'refused',
        );
      }
      await d.expectLine('Inspect', 'parses');
      await d.expectLine('Detect hidden data', 'never found');
    }
  });

  testWidgets('the recipe picks are applied and damage is caught', (_) async {
    final d = PlayDriver(StegoPlayground(CipherBird.instance));
    d.pick('Carrier', 'photo 1024x1024 PPM');
    await d.expectLine('New carrier', 'room for');
    d.pick('Mode', 'recipe (custom pipeline)');
    d.pick('Recipe key', 'key photo');
    d.pick('Recipe layers', 'all four cascaded');
    d.pick('Recipe error correction', 'Hamming(7,4)');
    d.pick('Recipe signature', 'hybrid Ed25519 + ML-DSA');
    final described = await d.press('Describe recipe');
    expect(described, contains('hamming74'));
    expect(described, contains('keyBytes'));
    await d.expectLine('Hide', 'carrier bytes changed');
    await d.expectLine('Reveal', secret);
    await d.expectLine('Reveal with the wrong key', 'refused');
    d.pick('Mode', 'encrypted');
    await d.expectLine('Hide', 'carrier bytes changed');
    await d.expectLine('Damage heavily', 'rewritten');
    expect(await d.press('Reveal'), isNot(contains(secret)));
  });
}
