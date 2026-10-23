import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird_example/play/live_playground.dart';
import 'package:cipherbird_example/play/playground_page.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import 'support/play_driver.dart';

/// Streams a generated photo through the live source, checks the credit
/// flows, draws a key, encrypts and decrypts under it, and shows a fresh
/// key refuses the old ciphertext; then tries the camera, which counts only
/// where one exists and the app may use it:
/// `flutter test integration_test/live_playground_test.dart -d <device id>`.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  setUpAll(CipherBird.preload);

  testWidgets('a streamed file earns credit and the generator opens', (
    _,
  ) async {
    final d = PlayDriver(LivePlayground(CipherBird.instance));
    await d.expectLine('New source', 'seeds after 256 credited bits');
    await d.expectLine('Draw key', 'refused: LiveEntropy: not ready');
    await d.expectLine('Stream', 'streaming a generated 512x512 photo');
    await Future<void>.delayed(const Duration(seconds: 2));
    await d.expectLine('Stop stream', 'stream stopped');
    await d.expectLine('Status', 'ready');
    expect(d.model.log.first, contains('credited'));
    expect(d.read('Key drawn from the stream (hex, 32 bytes)'), hasLength(64));
    expect(d.read('Ciphertext (base64)'), isNotEmpty);
    await d.expectLine('Decrypt', 'decrypted: pier 9 at dawn');
    d.pick('Key refresh', 'manual');
    await d.expectLine('New source', 'seeds after');
    await d.expectLine('Stream', 'streaming');
    await Future<void>.delayed(const Duration(seconds: 1));
    await d.expectLine('Stop stream', 'stream stopped');
    expect(d.read('Key drawn from the stream (hex, 32 bytes)'), isEmpty);
    await d.expectLine('Draw key', 'seeded first');
    await d.expectLine('Encrypt', 'XChaCha20-Poly1305');
    await d.expectLine('Decrypt', 'decrypted: pier 9 at dawn');
    await d.expectLine('Draw key', 'key drawn from the stream');
    await d.expectLine('Decrypt', 'refused');
  });

  testWidgets('the camera feeds frames where it is available', (tester) async {
    final model = LivePlayground(CipherBird.instance);
    final d = PlayDriver(model);
    await tester.pumpWidget(MaterialApp(home: PlaygroundPage(model)));
    await d.press('New source');
    final line = await d.press('Start camera');
    if (!line.contains('streaming at')) {
      debugPrint('camera not exercised here: $line');
      return;
    }
    for (var i = 0; i < 100 && model.meter.value.chunks < 20; i++) {
      await tester.pump(const Duration(milliseconds: 200));
      await Future<void>.delayed(const Duration(milliseconds: 200));
      if (i % 10 == 9) {
        debugPrint(
          'camera wait ${i + 1}: ${model.meter.value.chunks} chunks, '
          'last line: ${model.log.first}',
        );
      }
    }
    await d.expectLine('Stop camera', 'camera stopped after');
    expect(d.model.log.first, isNot(contains('after 0 chunks')));
    await d.expectLine('Status', 'chunks fed');
  });
}
