// Runs on a device, simulator or emulator: exercises the platform key
// module end to end through the keyring.
//
//   flutter test integration_test -d <device id>
import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_hardware.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  const label = 'cipherbird-integration-test';

  setUpAll(() async {
    await CipherBird.preload();
    if (await HardwareKey.exists(label)) {
      await (await HardwareKey.open(label)).delete();
    }
  });

  testWidgets('hardware key wraps a keyring slot on this device', (_) async {
    final key = await HardwareKey.create(label);
    debugPrint('cipherbird hardware backing: ${key.backing}');
    expect(key.backing, isNot(HardwareBacking.none));

    final lib = CipherBird.instance;
    final kr = lib.keyringCreate();
    expect(
      lib.keyringAddPassphraseSlot(kr, 'pw', KdfPreset.interactive),
      isTrue,
    );
    final index = await lib.keyringAddHardwareSlot(kr, key);
    expect(lib.keyringSlotType(kr, index), 2);
    final blob = lib.keyringSerialise(kr);
    lib.keyringFree(kr);

    final loaded = lib.keyringDeserialise(blob);
    final reopened = await HardwareKey.open(label);
    expect(reopened.backing, key.backing);
    final master = await lib.keyringUnlockWithHardware(loaded, reopened);
    final byPass = lib.keyringUnlockWithPassphrase(
      lib.keyringDeserialise(blob),
      'pw',
    );
    expect(master.bytes, byPass);
    master.wipe();
    lib.keyringFree(loaded);

    final secret = SecretBytes.take(Uint8List.fromList(List.filled(32, 7)));
    final wrapped = await key.wrap(secret);
    expect(wrapped, isNot(equals(secret.bytes)));
    final back = await key.unwrap(wrapped);
    expect(back.bytes, secret.bytes);

    try {
      final att = await key.attest(Uint8List.fromList(List.filled(32, 1)));
      debugPrint(
        'cipherbird attestation: ${att.kind} ${att.document.length} bytes',
      );
    } on HardwareKeyException catch (e) {
      debugPrint('cipherbird attestation unavailable here: ${e.code}');
      expect(e.code, 'unsupported');
    }

    await key.delete();
    expect(await HardwareKey.exists(label), isFalse);
  });
}
