import 'dart:typed_data';

import 'package:cipherbird_benchmark/src/benchmark_table.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart' as cg;
import 'package:pointycastle/export.dart' as pc;

/// The digest rows of the suite on a 1 MiB input.
Future<void> addHashRows(
  BenchmarkTable table,
  CipherBird lib, {
  required Uint8List mib,
}) async {
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
}
