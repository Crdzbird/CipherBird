import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final lib = CryptoLib.instance;
  const inline = CryptoLibInlineRunner();
  const isolate = CryptoLibIsolateRunner(inlineThreshold: 0);

  for (final (name, runner) in [('inline', inline), ('isolate', isolate)]) {
    test('passphrase key derives off-thread with the $name runner', () async {
      final salt = lib.easy.randomBytes(16);
      final key = await lib.easy.symmetricKeyFromPassphraseAsync(
        'pw',
        salt: salt,
        runner: runner,
      );
      final same = SymmetricKey.fromPassphrase('pw', salt: salt);
      expect(key.hex, same.hex);
      expect(
        () => lib.easy.symmetricKeyFromPassphraseAsync(
          'pw',
          salt: Uint8List(4),
          runner: runner,
        ),
        throwsArgumentError,
      );
    });

    test('password hashing round-trips with the $name runner', () async {
      final phc = await lib.easy.hashPasswordAsync('hunter2', runner: runner);
      expect(
        await lib.easy.verifyPasswordAsync('hunter2', phc, runner: runner),
        isTrue,
      );
      expect(
        await lib.easy.verifyPasswordAsync('hunter3', phc, runner: runner),
        isFalse,
      );
    });
  }

  test(
    'preload warms through a runner and the lazy path still works',
    () async {
      expect(await CryptoLib.preload(runner: inline), isTrue);
      expect(await CryptoLib.preload(), isTrue);
      expect(lib.version(), isNotEmpty);
    },
  );
}
