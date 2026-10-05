import 'dart:math';
import 'dart:typed_data';

import 'package:cipherbird_benchmark/src/benchmark_table.dart';
import 'package:cipherbird_benchmark/src/slow_rows.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;

/// Runs the comparison suite against [lib] and returns the finished table.
Future<BenchmarkTable> runSuite(
  CipherBird lib, {
  required String label,
  required void Function(String line) log,
}) async {
  final rng = Random(7);
  Uint8List bytes(int n) =>
      Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
  final mib = bytes(1 << 20);
  final kib = bytes(1024);
  final key = bytes(32);
  final nonce12 = bytes(12);
  final salt = bytes(16);
  final table = BenchmarkTable([
    label,
    'pointycastle',
    'cryptography',
    'crypto',
  ], log: log);
  pc.AEADParameters<pc.KeyParameter> aead() =>
      pc.AEADParameters(pc.KeyParameter(key), 128, nonce12, Uint8List(0));
  final cgAes = cg.AesGcm.with256bits();
  final cgChacha = cg.Chacha20.poly1305Aead();
  final cgKey = cg.SecretKey(key);
  final ed = cg.Ed25519();
  final edPair = await ed.newKeyPair();
  final x = cg.X25519();
  final xPair = await x.newKeyPair();
  final xPeer = await (await x.newKeyPair()).extractPublicKey();
  final edKeys = lib.ed25519Keygen();
  final xKeys = lib.x25519Keygen();
  final xPeerKeys = lib.x25519Keygen();
  final edSig = lib.ed25519Sign(kib, edKeys.secretKey);
  final cgSig = await ed.sign(kib, keyPair: edPair);
  const passphrase = 'correct horse battery staple';

  await table.row('SHA-256, 1 MiB', [
    () async => lib.sha256(mib),
    () async => pc.SHA256Digest().process(mib),
    () async => cg.Sha256().hash(mib),
    () async => crypto.sha256.convert(mib),
  ], size: 1 << 20);
  await table.row('BLAKE2b-512, 1 MiB', [
    () async => lib.blake2b(mib),
    () async => pc.Blake2bDigest(digestSize: 64).process(mib),
    null,
    null,
  ], size: 1 << 20);
  await table.row('BLAKE3, 1 MiB', [
    () async => lib.blake3(mib),
    null,
    null,
    null,
  ], size: 1 << 20);
  await table.row('XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB', [
    () async => lib.xchacha20Encrypt(mib, key),
    () async => (pc.ChaCha20Poly1305(
      pc.ChaCha7539Engine(),
      pc.Poly1305(),
    )..init(true, aead())).process(mib),
    () async => cgChacha.encrypt(mib, secretKey: cgKey, nonce: nonce12),
    null,
  ], size: 1 << 20);
  await table.row('AES-256-GCM encrypt, 1 MiB', [
    () async => lib.aes256gcmEncrypt(mib, key),
    () async =>
        (pc.GCMBlockCipher(pc.AESEngine())..init(true, aead())).process(mib),
    () async => cgAes.encrypt(mib, secretKey: cgKey, nonce: nonce12),
    null,
  ], size: 1 << 20);
  await table.row('Ed25519 sign, 1 KiB', [
    () async => lib.ed25519Sign(kib, edKeys.secretKey),
    null,
    () async => ed.sign(kib, keyPair: edPair),
    null,
  ]);
  await table.row('Ed25519 verify, 1 KiB', [
    () async => lib.ed25519Verify(kib, edSig, edKeys.publicKey),
    null,
    () async => ed.verify(kib, signature: cgSig),
    null,
  ]);
  await table.row('X25519 shared secret', [
    () async => lib.x25519SharedSecret(xKeys.secretKey, xPeerKeys.publicKey),
    null,
    () async => x.sharedSecretKey(keyPair: xPair, remotePublicKey: xPeer),
    null,
  ]);
  await addSlowRows(table, lib, salt: salt, passphrase: passphrase);
  return table;
}
