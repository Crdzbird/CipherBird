import 'dart:typed_data';

import 'package:cipherbird_benchmark/src/benchmark_table.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;

/// The password-hashing and post-quantum rows of the suite.
Future<void> addSlowRows(
  BenchmarkTable table,
  CipherBird lib, {
  required Uint8List salt,
  required String passphrase,
}) async {
  final passwordBytes = Uint8List.fromList(passphrase.codeUnits);
  await table.row('Argon2id, 64 MiB, 2 passes', [
    () async => lib.argon2idDerive(passphrase, salt, ops: 2, mem: 64 << 20),
    () async {
      final generator = pc.Argon2BytesGenerator()
        ..init(
          pc.Argon2Parameters(
            pc.Argon2Parameters.ARGON2_id,
            salt,
            desiredKeyLength: 32,
            iterations: 2,
            memory: 64 << 10,
            lanes: 1,
          ),
        );
      generator.process(passwordBytes);
    },
    () async => cg.Argon2id(
      memory: 64 << 10,
      parallelism: 1,
      iterations: 2,
      hashLength: 32,
    ).deriveKey(secretKey: cg.SecretKey(passwordBytes), nonce: salt),
    null,
  ]);
  await table.row('ML-KEM-768 keygen + encapsulate + decapsulate', [
    () async {
      final kp = lib.mlKemKeygen(MlKemLevel.level768);
      final (ct, _) = lib.mlKemEncapsulate(kp.publicKey, MlKemLevel.level768);
      lib.mlKemDecapsulate(ct, kp.secretKey, MlKemLevel.level768);
    },
    null,
    null,
    null,
  ]);
  await table.row(
    'Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate',
    [
      () async {
        final kp = lib.hybridKemKeygen();
        final (ct, _) = lib.hybridKemEncapsulate(kp.publicKey);
        lib.hybridKemDecapsulate(ct, kp.secretKey);
      },
      null,
      null,
      null,
    ],
  );
}
