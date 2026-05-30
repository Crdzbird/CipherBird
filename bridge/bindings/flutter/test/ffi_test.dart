// Runtime FFI test: loads the native library and exercises the real dart:ffi
// binding (lib/cryptolib_ffi.dart) the GUI app uses. `flutter test` runs this on
// the host VM, so it actually marshals data across the C boundary — not just a
// static analyze. Assumes `make lib` has built build/release/libcryptolib_c.dylib.
//
// This is the FULL showcase: every capability family the binding exposes —
// hashing, symmetric AEAD, asymmetric, vaults, post-quantum, BLS, and the
// multi-slot keyring — round-tripped across FFI.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:cryptolib_gui/cryptolib_ffi.dart';

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List _u(String s) => Uint8List.fromList(s.codeUnits);
bool _eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void main() {
  final dylib = '../../../build/release/libcryptolib_c.dylib';

  test('native library is present', () {
    expect(File(dylib).existsSync(), isTrue,
        reason: 'run `make lib` first to build $dylib');
  });

  late CryptoLib lib;
  final abc = _u('abc');
  final msg = _u('secret payload');

  setUp(() {
    lib = CryptoLib.load(dylib);
    lib.init();
  });

  test('version', () => expect(lib.version(), '3.0.0'));

  test('hashing', () {
    expect(_hex(lib.sha256(abc)),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(lib.sha512(abc).length, 64);
    expect(lib.blake2b(abc).length, 64);
    final hk = lib.randomBytes(32);
    final mac = lib.hmacSha512(abc, hk);
    expect(lib.hmacSha512Verify(abc, mac, hk), isTrue);
    final phc =
        String.fromCharCodes(lib.argon2idHashStr('hunter2')).replaceAll('\x00', '');
    expect(lib.argon2idVerifyStr('hunter2', phc), isTrue);
  });

  test('symmetric AEAD', () {
    final sk = lib.randomBytes(32);
    final xct = lib.xchacha20Encrypt(msg, sk);
    expect(_eq(lib.xchacha20Decrypt(xct, sk), msg), isTrue);
    if (lib.aes256gcmAvailable()) {
      final act = lib.aes256gcmEncrypt(msg, sk);
      expect(_eq(lib.aes256gcmDecrypt(act, sk), msg), isTrue);
    }
  });

  test('asymmetric primitives', () {
    final ed = lib.ed25519Keygen();
    final sig = lib.ed25519Sign(abc, ed.secretKey);
    expect(lib.ed25519Verify(abc, sig, ed.publicKey), isTrue);

    final xa = lib.x25519Keygen(), xb = lib.x25519Keygen();
    expect(
        _eq(lib.x25519SharedSecret(xa.secretKey, xb.publicKey),
            lib.x25519SharedSecret(xb.secretKey, xa.publicKey)),
        isTrue);

    final r = lib.boxKeygen(), s = lib.boxKeygen();
    final bct = lib.boxEncrypt(msg, r.publicKey, s.secretKey);
    expect(_eq(lib.boxDecrypt(bct, s.publicKey, r.secretKey), msg), isTrue);

    final sct = lib.sealedboxEncrypt(msg, r.publicKey);
    expect(_eq(lib.sealedboxDecrypt(sct, r.publicKey, r.secretKey), msg), isTrue);
  });

  test('vaults', () {
    final vault = lib.vaultCreate(lib.randomBytes(32));
    final pkt = lib.vaultSeal(vault, msg, 'ctx');
    expect(_eq(lib.vaultOpen(vault, pkt, 'ctx'), msg), isTrue);
    lib.vaultFree(vault);

    final alice = lib.asymBundleGenerate(), bob = lib.asymBundleGenerate();
    final apkt = lib.asymVaultSeal(alice, bob.boxPublic, msg, 'ctx');
    expect(_eq(lib.asymVaultOpen(apkt, bob, alice.signPublic, 'ctx'), msg), isTrue);
  });

  test('post-quantum', () {
    final kem = lib.mlKemKeygen(1);
    final (kemCt, ssEnc) = lib.mlKemEncapsulate(kem.publicKey, 1);
    expect(_eq(ssEnc, lib.mlKemDecapsulate(kemCt, kem.secretKey, 1)), isTrue);

    final hkem = lib.hybridKemKeygen();
    final (hCt, hSsEnc) = lib.hybridKemEncapsulate(hkem.publicKey);
    expect(_eq(hSsEnc, lib.hybridKemDecapsulate(hCt, hkem.secretKey)), isTrue);
    expect(hSsEnc.length, 32);

    final dsa = lib.mlDsaKeygen(1);
    final dsig = lib.mlDsaSign(abc, dsa.secretKey, 1);
    expect(lib.mlDsaVerify(abc, dsig, dsa.publicKey, 1), isTrue);

    final slh = lib.slhDsaKeygen(1, 0);
    final ssig = lib.slhDsaSign(abc, slh.secretKey, 1, 0);
    expect(lib.slhDsaVerify(abc, ssig, slh.publicKey, 1, 0), isTrue);
  });

  test('BLS12-381', () {
    final bls = lib.blsKeygen();
    final bsig = lib.blsSign(abc, bls.secretKey);
    expect(lib.blsVerify(abc, bsig, bls.publicKey), isTrue);
  });

  test('keyring device == passphrase master', () {
    final factor = lib.randomBytes(32);
    final kr = lib.keyringCreate();
    lib.keyringAddDeviceSlot(kr, factor);
    lib.keyringAddPassphraseSlot(kr, 'cross-device pass', 0);
    expect(lib.keyringSlotCount(kr), 2);

    final blob = lib.keyringSerialise(kr);
    final kr2 = lib.keyringDeserialise(blob);
    final mDev = lib.keyringUnlockWithDevice(kr2, factor);
    final mPass = lib.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
    expect(_eq(mDev, mPass), isTrue);
    expect(mDev.length, 32);

    lib.keyringFree(kr);
    lib.keyringFree(kr2);
  });
}
