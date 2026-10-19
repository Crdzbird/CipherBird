@TestOn('vm')
library;

import 'dart:typed_data';

import 'package:cipherbird/cipherbird.dart';
import 'package:cipherbird/cipherbird_hardware.dart';
import 'package:flutter_test/flutter_test.dart';

/// A stand-in key module: wraps with the committing AEAD under a key the
/// keyring never sees, gated by a flag that mimics a cancelled prompt.
final class FakeModule implements HardwareBackend {
  final Map<String, Uint8List> _keys = {};
  bool refuseUnwrap = false;

  @override
  Future<HardwareBacking> create(
    String label, {
    required bool biometric,
  }) async {
    if (_keys.containsKey(label)) {
      throw const HardwareKeyException('exists', 'exists');
    }
    _keys[label] = CipherBird.instance.randomBytes(32);
    return HardwareBacking.strongBox;
  }

  @override
  Future<bool> exists(String label) async => _keys.containsKey(label);

  @override
  Future<void> delete(String label) async => _keys.remove(label);

  @override
  Future<HardwareBacking> backing(String label) async =>
      HardwareBacking.strongBox;

  @override
  Future<Uint8List> wrap(String label, Uint8List input) async =>
      CipherBird.instance.committingEncrypt(input, _key(label));

  @override
  Future<Uint8List> unwrap(
    String label,
    Uint8List blob, {
    required String reason,
  }) async {
    if (refuseUnwrap) {
      throw const HardwareKeyException('authentication_failed', 'cancelled');
    }
    return CipherBird.instance.committingDecrypt(blob, _key(label));
  }

  @override
  Future<HardwareAttestation> attest(String label, Uint8List challenge) async =>
      HardwareAttestation(
        kind: AttestationKind.androidKeyAttestation,
        keyId: '$label.attest',
        document: challenge,
        publicKey: Uint8List(0),
      );

  Uint8List _key(String label) =>
      _keys[label] ??
      (throw const HardwareKeyException('not_found', 'missing'));
}

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;

  test('a hardware key wraps a keyring slot and unlocks it again', () async {
    final module = FakeModule();
    final key = await HardwareKey.create('bank-possession', backend: module);
    expect(key.backing, HardwareBacking.strongBox);
    final kr = lib.keyringCreate();
    expect(
      lib.keyringAddPassphraseSlot(kr, 'pw', KdfPreset.interactive),
      isTrue,
    );
    final index = await lib.keyringAddHardwareSlot(kr, key);
    expect(index, 1);
    expect(lib.keyringSlotType(kr, index), 2);
    final blob = lib.keyringSerialise(kr);
    expect(blob[4], 2);
    final loaded = lib.keyringDeserialise(blob);
    final reopened = await HardwareKey.open('bank-possession', backend: module);
    final master = await lib.keyringUnlockWithHardware(loaded, reopened);
    final byPass = lib.keyringUnlockWithPassphrase(
      lib.keyringDeserialise(blob),
      'pw',
    );
    expect(master.bytes, byPass);
    master.wipe();
    module.refuseUnwrap = true;
    await expectLater(
      lib.keyringUnlockWithHardware(loaded, reopened),
      throwsA(
        isA<HardwareKeyException>().having(
          (e) => e.isAuthenticationFailure,
          'auth',
          isTrue,
        ),
      ),
    );
    lib.keyringFree(loaded);
    lib.keyringFree(kr);
  });

  test('a missing key or slot is reported, not guessed', () async {
    final module = FakeModule();
    await expectLater(
      HardwareKey.open('nope', backend: module),
      throwsA(isA<HardwareKeyException>()),
    );
    final key = await HardwareKey.create('other', backend: module);
    final kr = lib.keyringCreate();
    expect(lib.keyringAddDeviceSlot(kr, lib.randomBytes(32)), isTrue);
    expect(lib.keyringHardwareSlotIndex(kr, key), -1);
    expect(() => lib.keyringHardwareSlot(kr, 0), throwsStateError);
    lib.keyringFree(kr);
  });

  test('the unsupported backend never falls back to software', () async {
    const backend = UnsupportedBackend('nowhere');
    await expectLater(
      HardwareKey.create('x', backend: backend),
      throwsA(
        isA<HardwareKeyException>().having(
          (e) => e.code,
          'code',
          'unsupported',
        ),
      ),
    );
    expect(await HardwareKey.exists('x', backend: backend), isFalse);
  });
}
