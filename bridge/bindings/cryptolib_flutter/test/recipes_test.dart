// CryptoLib recipes — composition in practice, verified against the host dylib.
//
// Real-world flows that snap primitives together (no new crypto, just wiring).
// Run: CRYPTOLIB_DYLIB=/abs/build/release/libcryptolib_c.dylib flutter test test/recipes_test.dart
//
// (Shamir threshold splitting is C++-only — not in the C ABI — so this mirrors
// the other five recipes; see example/recipes.cpp for all six.)
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_flutter/cryptolib_flutter.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  final lib = CryptoLib.instance;
  final aad = Uint8List.fromList('recipe/v1'.codeUnits);
  Uint8List B(String s) => Uint8List.fromList(s.codeUnits);
  bool eq(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  // 1. File-as-key vault: deterministic media entropy → master → MolecularVault.
  test('recipe 1 · file-as-key vault (media entropy → MolecularVault)', () {
    final tmp = File('${Directory.systemTemp.path}/cryptolib_flutter_recipe_key.bin');
    tmp.writeAsBytesSync(
        Uint8List.fromList(List.generate(4096, (i) => (i * 37 + 11) & 0xff)));
    try {
      final e1 = lib.entropyFromFileDeterministic(tmp.path);
      final master = lib.entropyDeriveAll(e1).vaultMasterKey;
      lib.entropyFree(e1);
      final env = lib.molecularSealWithKey(B('launch codes'), master, aad: aad);

      final e2 = lib.entropyFromFileDeterministic(tmp.path);
      final master2 = lib.entropyDeriveAll(e2).vaultMasterKey;
      lib.entropyFree(e2);
      expect(eq(lib.molecularOpenWithKey(env, master2, aad: aad), B('launch codes')), isTrue);
    } finally {
      tmp.deleteSync();
    }
  });

  // 2. Post-quantum message: hybrid KEM shared secret → MolecularVault.
  test('recipe 2 · post-quantum message (hybrid KEM → MolecularVault)', () {
    final bob = lib.hybridKemKeygen();
    final (ct, ss) = lib.hybridKemEncapsulate(bob.publicKey); // sender
    final env = lib.molecularSealWithKey(B('see you at dawn'), ss, aad: aad);
    final ss2 = lib.hybridKemDecapsulate(ct, bob.secretKey);  // recipient
    expect(eq(lib.molecularOpenWithKey(env, ss2, aad: aad), B('see you at dawn')), isTrue);
  });

  // 3. Sign-then-seal: hybrid signature carried inside a MolecularVault.
  test('recipe 3 · sign-then-seal (hybrid signature inside MolecularVault)', () {
    final signer = lib.hybridSigKeygen();
    final msg = B('transfer 100 to acct #42');
    final sig = lib.hybridSigSign(msg, signer.secretKey);
    final bundle = Uint8List.fromList([...msg, ...sig]);
    final env = lib.molecularSeal(bundle, 'outer passphrase', aad: aad, ops: 2, mem: 1 << 20);
    final opened = lib.molecularOpen(env, 'outer passphrase', aad: aad);
    final gotMsg = Uint8List.sublistView(opened, 0, msg.length);
    final gotSig = Uint8List.sublistView(opened, msg.length);
    expect(lib.hybridSigVerify(gotMsg, gotSig, signer.publicKey) && eq(gotMsg, msg), isTrue);
  });

  // 4. EVM wallet: secp256k1 → Keccak address → sign tx digest → ecrecover.
  test('recipe 4 · EVM wallet (secp256k1 → Keccak address → sign → ecrecover)', () {
    final w = lib.secp256k1Keygen();
    final addr = Uint8List.sublistView(
        lib.keccak256(Uint8List.sublistView(w.publicKey, 1)), 12, 32); // last 20 bytes
    expect(addr.length, 20);
    final digest = lib.keccak256(B('transfer 1 ETH'));
    final sig = lib.secp256k1Sign(digest, w.secretKey); // 65B r‖s‖v
    final recovered = lib.secp256k1Recover(digest, sig);
    expect(sig.length == 65 && eq(recovered, w.publicKey), isTrue);
  });

  // 5. Keyring-guarded vault: master under device + passphrase → MolecularVault.
  test('recipe 5 · keyring-guarded vault (Keyring unlock → MolecularVault key)', () {
    final deviceKey = lib.randomBytes(32);
    final kr = lib.keyringCreate();
    lib.keyringAddDeviceSlot(kr, deviceKey);
    lib.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
    final blob = lib.keyringSerialise(kr);
    final kr2 = lib.keyringDeserialise(blob);
    try {
      final master = lib.keyringUnlockWithDevice(kr2, deviceKey);
      final env = lib.molecularSealWithKey(B('root secret'), master, aad: aad);
      final master2 = lib.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
      expect(eq(lib.molecularOpenWithKey(env, master2, aad: aad), B('root secret')) &&
          eq(master, master2), isTrue);
    } finally {
      lib.keyringFree(kr);
      lib.keyringFree(kr2);
    }
  });
}
