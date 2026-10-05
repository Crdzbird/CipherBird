// CryptoLib Dart — FULL showcase of every capability family via dart:ffi.
//   dart pub get && dart run bin/showcase.dart <path-to-libcryptolib_c.dylib>

import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

int pass = 0, fail = 0;
void ck(String l, bool ok) {
  print('  ${ok ? "✓" : "✗"} $l');
  ok ? pass++ : fail++;
}

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
Uint8List u(String s) => Uint8List.fromList(s.codeUnits);
bool eq(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
  return true;
}

void main(List<String> args) {
  final lib = CryptoLib.load(
      args.isNotEmpty ? args[0] : 'build/release/libcryptolib_c.dylib');
  lib.init();
  print('CryptoLib ${lib.version()} — Dart full showcase\n');
  final abc = u('abc'), msg = u('secret payload');

  print('HASHING');
  ck(
      'SHA-256(abc) KAT',
      hex(lib.sha256(abc)) ==
          'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  ck('SHA-512', lib.sha512(abc).length == 64);
  ck('BLAKE2b', lib.blake2b(abc).length == 64);
  final hk = lib.randomBytes(32);
  final mac = lib.hmacSha512(abc, hk);
  ck('HMAC-SHA512 verify', lib.hmacSha512Verify(abc, mac, hk));
  final phc = String.fromCharCodes(lib.argon2idHashStr('hunter2'))
      .replaceAll('\x00', '');
  ck('Argon2id PHC verify', lib.argon2idVerifyStr('hunter2', phc));

  print('\nSYMMETRIC');
  final sk = lib.randomBytes(32);
  final xct = lib.xchacha20Encrypt(msg, sk);
  ck('XChaCha20 round-trip', eq(lib.xchacha20Decrypt(xct, sk), msg));
  if (lib.aes256gcmAvailable()) {
    final act = lib.aes256gcmEncrypt(msg, sk);
    ck('AES-256-GCM round-trip', eq(lib.aes256gcmDecrypt(act, sk), msg));
  } else {
    print('    AES-256-GCM unavailable');
  }

  print('\nASYMMETRIC');
  final ed = lib.ed25519Keygen();
  final sig = lib.ed25519Sign(abc, ed.secretKey);
  ck('Ed25519 sign/verify', lib.ed25519Verify(abc, sig, ed.publicKey));
  final xa = lib.x25519Keygen(), xb = lib.x25519Keygen();
  ck(
      'X25519 ECDH',
      eq(lib.x25519SharedSecret(xa.secretKey, xb.publicKey),
          lib.x25519SharedSecret(xb.secretKey, xa.publicKey)));
  final r = lib.boxKeygen(), s = lib.boxKeygen();
  final bct = lib.boxEncrypt(msg, r.publicKey, s.secretKey);
  ck('Box round-trip', eq(lib.boxDecrypt(bct, s.publicKey, r.secretKey), msg));
  final sct = lib.sealedboxEncrypt(msg, r.publicKey);
  ck('SealedBox round-trip',
      eq(lib.sealedboxDecrypt(sct, r.publicKey, r.secretKey), msg));

  print('\nVAULTS');
  final vault = lib.vaultCreate(lib.randomBytes(32));
  final pkt = lib.vaultSeal(vault, msg, 'ctx');
  ck('SecureVault round-trip', eq(lib.vaultOpen(vault, pkt, 'ctx'), msg));
  lib.vaultFree(vault);
  final alice = lib.asymBundleGenerate(), bob = lib.asymBundleGenerate();
  final apkt = lib.asymVaultSeal(alice, bob.boxPublic, msg, 'ctx');
  ck('AsymmetricVault round-trip',
      eq(lib.asymVaultOpen(apkt, bob, alice.signPublic, 'ctx'), msg));

  print('\nPOST-QUANTUM');
  final kem = lib.mlKemKeygen(MlKemLevel.level768);
  final (kemCt, ssEnc) =
      lib.mlKemEncapsulate(kem.publicKey, MlKemLevel.level768);
  ck(
      'ML-KEM-768 encaps/decaps',
      eq(ssEnc,
          lib.mlKemDecapsulate(kemCt, kem.secretKey, MlKemLevel.level768)));
  final hkem = lib.hybridKemKeygen();
  final (hCt, hSsEnc) = lib.hybridKemEncapsulate(hkem.publicKey);
  ck(
      'Hybrid X25519+ML-KEM-768 encaps/decaps',
      eq(hSsEnc, lib.hybridKemDecapsulate(hCt, hkem.secretKey)) &&
          hSsEnc.length == 32);
  final dsa = lib.mlDsaKeygen(MlDsaLevel.level65);
  final dsig = lib.mlDsaSign(abc, dsa.secretKey, MlDsaLevel.level65);
  ck('ML-DSA-65 sign/verify',
      lib.mlDsaVerify(abc, dsig, dsa.publicKey, MlDsaLevel.level65));
  final slh = lib.slhDsaKeygen(SlhDsaLevel.fast128, SlhDsaHash.sha2);
  final ssig =
      lib.slhDsaSign(abc, slh.secretKey, SlhDsaLevel.fast128, SlhDsaHash.sha2);
  ck(
      'SLH-DSA-128f sign/verify',
      lib.slhDsaVerify(
          abc, ssig, slh.publicKey, SlhDsaLevel.fast128, SlhDsaHash.sha2));

  print('\nBLS12-381');
  final bls = lib.blsKeygen();
  final bsig = lib.blsSign(abc, bls.secretKey);
  ck('BLS sign/verify', lib.blsVerify(abc, bsig, bls.publicKey));

  print('\nKEYRING');
  final factor = lib.randomBytes(32);
  final kr = lib.keyringCreate();
  lib.keyringAddDeviceSlot(kr, factor);
  lib.keyringAddPassphraseSlot(kr, 'cross-device pass', KdfPreset.interactive);
  final blob = lib.keyringSerialise(kr);
  final kr2 = lib.keyringDeserialise(blob);
  ck(
      'Keyring device==passphrase master (${lib.keyringSlotCount(kr)} slots)',
      eq(lib.keyringUnlockWithDevice(kr2, factor),
          lib.keyringUnlockWithPassphrase(kr2, 'cross-device pass')));
  lib.keyringFree(kr);
  lib.keyringFree(kr2);

  print(
      '\nDart showcase ${fail == 0 ? "OK" : "FAILED"} ($pass passed, $fail failed)');
  exit(fail == 0 ? 0 : 1);
}
