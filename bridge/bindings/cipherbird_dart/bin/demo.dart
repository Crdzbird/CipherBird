// Standalone dart:ffi console demo for CipherBird.
//
// Reuses the same bindings the Flutter plugin uses (lib/cryptolib_ffi.dart).
// Run (see Makefile target `dart`):
//   dart pub get
//   dart run bin/demo.dart <path-to-libcipherbird.dylib>

import 'dart:io';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';

String hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main(List<String> args) {
  final path = args.isNotEmpty ? args[0] : null;

  final lib = CipherBird.load(path);
  lib.init();
  stdout.writeln('CipherBird version: ${lib.version()}');
  stdout.writeln('random(32):  ${hex(lib.randomBytes(32))}');
  stdout.writeln(
    'sha256(abc): ${hex(lib.sha256(Uint8List.fromList('abc'.codeUnits)))}',
  );

  // BLAKE3 — primary hash + keyed MAC + KDF (domain separation).
  final abc = Uint8List.fromList('abc'.codeUnits);
  final b3 = lib.blake3(abc);
  final b3xof = lib.blake3(abc, outLen: 64);
  // XOF property: the 32-byte digest is the prefix of the extended output.
  final xofPrefixOk = hex(b3) == hex(Uint8List.sublistView(b3xof, 0, 32));
  final key = lib.randomBytes(32);
  final mac = lib.blake3Keyed(abc, key);
  final macDiffers = hex(mac) != hex(b3); // keyed output != unkeyed
  final k1 = lib.blake3DeriveKey('cryptolib demo 2026 context-A', abc);
  final k2 = lib.blake3DeriveKey('cryptolib demo 2026 context-B', abc);
  final domainSep = hex(k1) != hex(k2); // different context → different key
  stdout.writeln('blake3(abc): ${hex(b3)}');
  stdout.writeln(
    'blake3 xof/keyed/kdf ok: '
    '${xofPrefixOk && b3.length == 32 && mac.length == 32 && macDiffers && domainSep}',
  );

  // BLS12-381 aggregate signatures — N sigs → 1, verify in ~1 op.
  // Basic scheme: each signer signs a DISTINCT message.
  final msgs = [
    Uint8List.fromList('block#1 commit'.codeUnits),
    Uint8List.fromList('block#2 commit'.codeUnits),
    Uint8List.fromList('block#3 commit'.codeUnits),
  ];
  final kps = List.generate(msgs.length, (_) => lib.blsKeygen());
  final sigs = [
    for (var i = 0; i < msgs.length; i++)
      lib.blsSign(msgs[i], kps[i].secretKey),
  ];
  final aggSig = lib.blsAggregate(sigs);
  final pks = [for (final kp in kps) kp.publicKey];
  final aggOk = lib.blsAggregateVerify(msgs, pks, aggSig);
  // Negative: tamper one message → aggregate must fail.
  final tampered = [...msgs]
    ..[1] = Uint8List.fromList('block#2 FORGED'.codeUnits);
  final aggReject = !lib.blsAggregateVerify(tampered, pks, aggSig);
  stdout.writeln(
    'bls aggregate(${sigs.length}->1) len=${aggSig.length} '
    'verify=$aggOk reject-tampered=$aggReject',
  );

  // Committing AEAD (UtC) — ciphertext binds the key; wrong key must fail.
  final caKey = lib.randomBytes(32);
  final caCt = lib.committingEncrypt(
    Uint8List.fromList('commit me'.codeUnits),
    caKey,
    Uint8List.fromList('ctx'.codeUnits),
  );
  final caPt = lib.committingDecrypt(
    caCt,
    caKey,
    Uint8List.fromList('ctx'.codeUnits),
  );
  var caReject = false;
  try {
    lib.committingDecrypt(
      caCt,
      lib.randomBytes(32),
      Uint8List.fromList('ctx'.codeUnits),
    );
  } catch (_) {
    caReject = true;
  }
  stdout.writeln(
    'committing AEAD: roundtrip="${String.fromCharCodes(caPt)}" '
    'reject-wrong-key=$caReject',
  );

  // HKDF-SHA256 + HMAC-SHA256.
  final ikm = lib.randomBytes(32);
  final prk = lib.hkdfExtract(ikm, salt: Uint8List.fromList('salt'.codeUnits));
  final okm = lib.hkdfExpand(
    prk,
    info: Uint8List.fromList('app'.codeUnits),
    outLen: 42,
  );
  final okm1 = lib.hkdfDerive(
    ikm,
    salt: Uint8List.fromList('salt'.codeUnits),
    info: Uint8List.fromList('app'.codeUnits),
    outLen: 42,
  );
  final hkdfConsistent = hex(okm) == hex(okm1); // one-shot == extract+expand
  final macMsg = Uint8List.fromList('mac me'.codeUnits);
  final hmac = lib.hmacSha256(macMsg, ikm);
  final hmacOk = lib.hmacSha256Verify(macMsg, hmac, ikm);
  final hmacReject = !lib.hmacSha256Verify(macMsg, hmac, lib.randomBytes(32));
  stdout.writeln(
    'hkdf len=${okm.length} consistent=$hkdfConsistent · '
    'hmac256 verify=$hmacOk reject=$hmacReject',
  );

  // Hybrid signature (Ed25519 + ML-DSA-65) — both must verify.
  final hsk = lib.hybridSigKeygen();
  final hmsg = Uint8List.fromList('sign me'.codeUnits);
  final hsig = lib.hybridSigSign(hmsg, hsk.secretKey);
  final hsigOk = lib.hybridSigVerify(hmsg, hsig, hsk.publicKey);
  final hsigReject = !lib.hybridSigVerify(
    Uint8List.fromList('forged'.codeUnits),
    hsig,
    hsk.publicKey,
  );
  stdout.writeln(
    'hybrid sig: len=${hsig.length} verify=$hsigOk reject=$hsigReject',
  );

  // BLS deterministic keygen — same IKM → same key.
  final blsIkm = lib.randomBytes(32);
  final d1 = lib.blsKeygenFromIkm(blsIkm);
  final d2 = lib.blsKeygenFromIkm(blsIkm);
  stdout.writeln(
    'bls keygen-from-ikm deterministic: '
    '${hex(d1.publicKey) == hex(d2.publicKey)}',
  );

  // EVM/BTC interop — Keccak-256, RIPEMD-160, secp256k1 ECDSA.
  // Keccak-256 KAT (Ethereum, NOT SHA3): keccak256("abc").
  final k = lib.keccak256(Uint8List.fromList('abc'.codeUnits));
  stdout.writeln('keccak256(abc): ${hex(k)}');
  final r160 = lib.ripemd160(Uint8List.fromList('abc'.codeUnits));
  stdout.writeln('ripemd160(abc): ${hex(r160)} (len=${r160.length})');

  // Derive an Ethereum address from a secp256k1 keypair:
  //   address = last 20 bytes of keccak256(uncompressed_pubkey[1:]).
  final ecKp = lib.secp256k1Keygen();
  final pubNoPrefix = Uint8List.sublistView(ecKp.publicKey, 1); // drop 0x04
  final addr = Uint8List.sublistView(lib.keccak256(pubNoPrefix), 12); // last 20
  stdout.writeln('eth address:    0x${hex(addr)}');

  // Sign a 32-byte digest, verify, and ecrecover the signer's pubkey.
  final digest = lib.keccak256(Uint8List.fromList('transaction'.codeUnits));
  final ecSig = lib.secp256k1Sign(digest, ecKp.secretKey); // 65: r‖s‖v
  final sig64 = Uint8List.sublistView(ecSig, 0, 64);
  final ecVerify = lib.secp256k1Verify(digest, sig64, ecKp.publicKey);
  final recovered = lib.secp256k1Recover(digest, ecSig);
  final recoverOk = hex(recovered) == hex(ecKp.publicKey);
  stdout.writeln(
    'secp256k1: sig=${ecSig.length}B verify=$ecVerify '
    'recover==signer=$recoverOk',
  );

  final vault = lib.vaultCreate(lib.randomBytes(32));
  final pkt = lib.vaultSeal(
    vault,
    Uint8List.fromList('hello from dart'.codeUnits),
    'ctx',
  );
  final opened = lib.vaultOpen(vault, pkt, 'ctx');
  stdout.writeln('vault roundtrip: "${String.fromCharCodes(opened)}"');

  lib.vaultFree(vault);

  // Keyring: default device slot + opt-in passphrase slot → cross-device unlock.
  final factor = lib.randomBytes(32); // stands in for a hardware factor key
  final kr = lib.keyringCreate();
  lib.keyringAddDeviceSlot(kr, factor);
  lib.keyringAddPassphraseSlot(kr, 'cross-device pass', KdfPreset.interactive);
  final blob = lib.keyringSerialise(kr);
  final kr2 = lib.keyringDeserialise(blob);
  final mDev = lib.keyringUnlockWithDevice(kr2, factor);
  final mPass = lib.keyringUnlockWithPassphrase(kr2, 'cross-device pass');
  final beforeRemove = lib.keyringSlotCount(kr);
  final removed = lib.keyringRemoveSlot(kr, 1); // revoke the passphrase slot
  stdout.writeln(
    'keyring slots: $beforeRemove '
    '· device==passphrase master: ${hex(mDev) == hex(mPass)} '
    '· removed-slot=$removed now=${lib.keyringSlotCount(kr)}',
  );
  lib.keyringFree(kr);
  lib.keyringFree(kr2);

  stdout.writeln('Dart demo OK');
}
