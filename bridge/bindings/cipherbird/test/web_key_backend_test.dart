@TestOn('browser')
library;

import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_hardware.dart';
import 'package:flutter_test/flutter_test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  final label = 'test-${DateTime.now().microsecondsSinceEpoch}';

  tearDownAll(() async {
    if (await HardwareKey.exists(label)) {
      await (await HardwareKey.open(label)).delete();
    }
  });

  test('a browser key wraps and unwraps, and only it unwraps', () async {
    final key = await HardwareKey.create(label);
    expect(key.backing, HardwareBacking.browser);
    expect(key.backing.isHardware, isFalse);
    expect(await HardwareKey.exists(label), isTrue);
    final secret = Uint8List.fromList(List.generate(32, (i) => i));
    final blob = await key.wrap(SecretBytes.take(Uint8List.fromList(secret)));
    expect(blob.length, 32 + 28);
    final back = await key.unwrap(blob, reason: 'test');
    expect(back.bytes, secret);
    final other = await HardwareKey.create('$label-other');
    await expectLater(
      other.unwrap(blob, reason: 'test'),
      throwsA(isA<HardwareKeyException>()),
    );
    await other.delete();
    await expectLater(
      HardwareKey.create(label),
      throwsA(isA<HardwareKeyException>()),
    );
    await expectLater(
      key.attest(Uint8List(32)),
      throwsA(isA<HardwareKeyException>()),
    );
  });

  test('a keyring slot wrapped by the browser key unlocks', () async {
    final key = await HardwareKey.open(label);
    final kr = lib.keyringCreate();
    try {
      final index = await lib.keyringAddHardwareSlot(kr, key);
      expect(lib.keyringSlotType(kr, index), 2);
      final master = await lib.keyringUnlockWithHardware(kr, key);
      expect(master.bytes, hasLength(32));
      final stored = lib.keyringSerialise(kr);
      final again = lib.keyringDeserialise(stored);
      try {
        final opened = await lib.keyringUnlockWithHardware(again, key);
        expect(opened.bytes, master.bytes);
      } finally {
        lib.keyringFree(again);
      }
    } finally {
      lib.keyringFree(kr);
    }
  });
}
