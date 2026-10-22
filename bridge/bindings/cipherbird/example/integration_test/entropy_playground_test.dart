import 'package:cipherbird/cipherbird.dart';

import 'support/play_driver.dart';

import 'package:cipherbird_example/play/entropy_playground.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

/// Runs the LavaRand playground on a device and checks the policy, the
/// harvest modes and every use of the harvest:
/// `flutter test integration_test/entropy_playground_test.dart -d <device id>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(CipherBird.preload);

  testWidgets('a photo passes the policy and feeds every consumer', (_) async {
    final d = PlayDriver(EntropyPlayground(CipherBird.instance));
    await d.expectLine('New source', 'repetition-count test passed');
    await d.expectLine('Harvest', 'harvested fresh');
    await d.expectLine('Harvest twice', 'two fresh harvests differ');
    d.pick('Harvest', 'deterministic (the file alone, reproducible)');
    await d.expectLine('Harvest', 'harvested deterministically');
    await d.expectLine('Harvest twice', 'agree byte for byte');
    await d.expectLine('Derive keys', 'sign public');
    await d.expectLine('Seal with the file', 'another photo refused');
    await d.expectLine('Seed a DRBG', 'replays the stream');
    await d.expectLine('Feed Fortuna', 'and again');
    d.pick('Recipe profile', 'high');
    d.pick('Recipe error correction', 'repetition x3');
    d.pick('Recipe signature', 'Ed25519');
    await d.expectLine('Recipe keyed by the file', 'another photo refused');
  });

  testWidgets('a flat image is refused until the policy is relaxed', (_) async {
    final d = PlayDriver(EntropyPlayground(CipherBird.instance));
    d.pick('Source', 'flat colour PPM (weak)');
    await d.expectLine('New source', 'repetition-count test FAILED');
    await d.expectLine('Harvest', 'policy refused the source');
    d.set('Policy floor, min-entropy bits per byte', '0');
    await d.expectLine('Harvest', 'policy refused the source');
    d.pick('Repetition-count test', 'reported only');
    await d.expectLine('Harvest', 'harvested fresh');
    d.pick('Source', 'tone WAV');
    await d.expectLine('New source', 'repetition-count test passed');
    await d.expectLine('Harvest', 'harvested fresh');
  });
}
