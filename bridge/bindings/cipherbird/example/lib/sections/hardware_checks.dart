import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_hardware.dart';
import 'package:cipherbird_example/checks/check.dart';
import 'package:cipherbird_example/util/bytes.dart';

/// A platform key module key wrapping a keyring slot, with attestation.
final class HardwareChecks {
  const HardwareChecks._();

  static const _label = 'cipherbird-showcase';

  static Future<HardwareKey> _fresh() async {
    try {
      if (await HardwareKey.exists(_label)) {
        await (await HardwareKey.open(_label)).delete();
      }
      return await HardwareKey.create(_label);
    } on HardwareKeyException catch (e) {
      throw SkipCheck('${e.code}: ${e.message}');
    }
  }

  static List<Check> build(CipherBird lib) => [
    Check('Create a hardware-backed key', () async {
      final key = await _fresh();
      return 'backing: ${key.backing.name}';
    }),
    Check('Wrap and unwrap a secret', () async {
      final key = await _fresh();
      final secret = SecretBytes.take(Uint8List.fromList(List.filled(32, 7)));
      final wrapped = await key.wrap(secret);
      final back = await key.unwrap(wrapped);
      demand(same(back.bytes, secret.bytes), 'mismatch');
      back.wipe();
      return '${wrapped.length}-byte wrapped blob';
    }),
    Check('Keyring hardware slot', () async {
      final key = await _fresh();
      final kr = lib.keyringCreate();
      final index = await lib.keyringAddHardwareSlot(kr, key);
      final blob = lib.keyringSerialise(kr);
      lib.keyringFree(kr);
      final again = lib.keyringDeserialise(blob);
      final master = await lib.keyringUnlockWithHardware(again, key);
      lib.keyringFree(again);
      master.wipe();
      return 'slot $index unlocked by the ${key.backing.name} key';
    }),
    Check('Attestation', () async {
      final key = await _fresh();
      try {
        final att = await key.attest(Uint8List.fromList(List.filled(32, 1)));
        return '${att.kind.name}, ${att.document.length}-byte document';
      } on HardwareKeyException catch (e) {
        throw SkipCheck('${e.code}: ${e.message}');
      } finally {
        await key.delete();
      }
    }),
  ];
}
