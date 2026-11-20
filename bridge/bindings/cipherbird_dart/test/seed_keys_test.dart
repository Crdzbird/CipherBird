import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;

  test('x-wing from a 32-byte seed is deterministic', () {
    final seed = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final a = lib.xwingKeypairFromSeed(seed);
    expect(a.publicKey.length, 1216);
    expect(lib.xwingKeypairFromSeed(seed).publicKey, a.publicKey);
  });

  test('x-wing refuses a seed that is not 32 bytes', () {
    for (final n in [0, 16, 31, 33, 64]) {
      expect(
        () => lib.xwingKeypairFromSeed(Uint8List(n)),
        throwsArgumentError,
      );
    }
  });

  test('bls refuses ikm shorter than 32 bytes', () {
    for (final n in [0, 8, 31]) {
      expect(() => lib.blsKeygenFromIkm(Uint8List(n)), throwsArgumentError);
    }
  });
}
