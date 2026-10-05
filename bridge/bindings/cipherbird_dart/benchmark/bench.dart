import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;

final lib = CryptoLib.instance;
final rng = Random(7);
Uint8List bytes(int n) => Uint8List.fromList(List.generate(n, (_) => rng.nextInt(256)));
final mib = bytes(1 << 20);
final kib = bytes(1024);
final key = bytes(32);
final nonce24 = bytes(24);
final nonce12 = bytes(12);
final salt = bytes(16);
final rows = <List<String>>[];

Future<double> opsPerSecond(Future<void> Function() op, {Duration budget = const Duration(seconds: 2)}) async {
  await op();
  final sw = Stopwatch()..start();
  var runs = 0;
  while (sw.elapsed < budget) {
    await op();
    runs++;
  }
  return runs / (sw.elapsedMicroseconds / 1e6);
}

String mbps(double ops, int size) => '${(ops * size / (1 << 20)).toStringAsFixed(0)} MB/s';
String ops(double v) => v >= 100 ? '${v.toStringAsFixed(0)} ops/s' : '${v.toStringAsFixed(1)} ops/s';

Future<void> row(String name, Map<String, Future<void> Function()?> impls, {int? size}) async {
  final cells = <String>[name];
  double? base;
  for (final entry in impls.entries) {
    if (entry.value == null) {
      cells.add('n/a');
      continue;
    }
    try {
      final v = await opsPerSecond(entry.value!);
      base ??= v;
      final text = size == null ? ops(v) : mbps(v, size);
      cells.add(entry.key == impls.keys.first ? text : '$text (${(base / v).toStringAsFixed(1)}x slower)');
    } on Object catch (e) {
      cells.add('error: ${e.runtimeType}');
    }
  }
  rows.add(cells);
  stderr.writeln(cells.join(' | '));
}

Future<void> main() async {
  final pcGcm = () {
    final c = pc.GCMBlockCipher(pc.AESEngine())
      ..init(true, pc.AEADParameters(pc.KeyParameter(key), 128, nonce12, Uint8List(0)));
    return c;
  };
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

  await row('SHA-256, 1 MiB', {
    'cipherbird': () async => lib.sha256(mib),
    'pointycastle': () async => pc.SHA256Digest().process(mib),
    'cryptography': () async => cg.Sha256().hash(mib),
    'crypto': () async => crypto.sha256.convert(mib),
  }, size: 1 << 20);
  await row('BLAKE2b-512, 1 MiB', {
    'cipherbird': () async => lib.blake2b(mib),
    'pointycastle': () async => pc.Blake2bDigest(digestSize: 64).process(mib),
    'cryptography': null,
    'crypto': null,
  }, size: 1 << 20);
  await row('BLAKE3, 1 MiB', {
    'cipherbird': () async => lib.blake3(mib),
    'pointycastle': null,
    'cryptography': null,
    'crypto': null,
  }, size: 1 << 20);
  await row('XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB', {
    'cipherbird': () async => lib.xchacha20Encrypt(mib, key),
    'pointycastle': () async => (pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
          ..init(true, pc.AEADParameters(pc.KeyParameter(key), 128, nonce12, Uint8List(0))))
        .process(mib),
    'cryptography': () async => cgChacha.encrypt(mib, secretKey: cgKey, nonce: nonce12),
    'crypto': null,
  }, size: 1 << 20);
  await row('AES-256-GCM encrypt, 1 MiB', {
    'cipherbird': () async => lib.aes256gcmEncrypt(mib, key),
    'pointycastle': () async => pcGcm().process(mib),
    'cryptography': () async => cgAes.encrypt(mib, secretKey: cgKey, nonce: nonce12),
    'crypto': null,
  }, size: 1 << 20);
  await row('Ed25519 sign, 1 KiB', {
    'cipherbird': () async => lib.ed25519Sign(kib, edKeys.secretKey),
    'pointycastle': null,
    'cryptography': () async => ed.sign(kib, keyPair: edPair),
    'crypto': null,
  });
  await row('Ed25519 verify, 1 KiB', {
    'cipherbird': () async => lib.ed25519Verify(kib, edSig, edKeys.publicKey),
    'pointycastle': null,
    'cryptography': () async => ed.verify(kib, signature: cgSig),
    'crypto': null,
  });
  await row('X25519 shared secret', {
    'cipherbird': () async => lib.x25519SharedSecret(xKeys.secretKey, xPeerKeys.publicKey),
    'pointycastle': null,
    'cryptography': () async => x.sharedSecretKey(keyPair: xPair, remotePublicKey: xPeer),
    'crypto': null,
  });
  await row('Argon2id, 64 MiB, 2 passes', {
    'cipherbird': () async => lib.argon2idDerive('correct horse battery staple', salt, ops: 2, mem: 64 << 20),
    'pointycastle': () async {
      final g = pc.Argon2BytesGenerator()
        ..init(pc.Argon2Parameters(pc.Argon2Parameters.ARGON2_id, salt,
            desiredKeyLength: 32, iterations: 2, memory: 64 << 10, lanes: 1));
      g.process(Uint8List.fromList('correct horse battery staple'.codeUnits));
    },
    'cryptography': () async => cg.Argon2id(memory: 64 << 10, parallelism: 1, iterations: 2, hashLength: 32)
        .deriveKey(secretKey: cg.SecretKey('correct horse battery staple'.codeUnits), nonce: salt),
    'crypto': null,
  });
  await row('ML-KEM-768 keygen + encapsulate + decapsulate', {
    'cipherbird': () async {
      final kp = lib.mlKemKeygen(MlKemLevel.level768);
      final (ct, _) = lib.mlKemEncapsulate(kp.publicKey, MlKemLevel.level768);
      lib.mlKemDecapsulate(ct, kp.secretKey, MlKemLevel.level768);
    },
    'pointycastle': null,
    'cryptography': null,
    'crypto': null,
  });
  await row('Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate', {
    'cipherbird': () async {
      final kp = lib.hybridKemKeygen();
      final (ct, _) = lib.hybridKemEncapsulate(kp.publicKey);
      lib.hybridKemDecapsulate(ct, kp.secretKey);
    },
    'pointycastle': null,
    'cryptography': null,
    'crypto': null,
  });

  final out = StringBuffer()
    ..writeln('| Operation | cipherbird (native) | pointycastle | cryptography | crypto |')
    ..writeln('|---|---|---|---|---|');
  for (final r in rows) {
    out.writeln('| ${r.join(' | ')} |');
  }
  stdout.write(out);
}
