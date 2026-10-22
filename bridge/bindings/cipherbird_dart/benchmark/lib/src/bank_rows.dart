import 'dart:typed_data';

import 'package:cipherbird_benchmark/src/bank_helpers.dart';
import 'package:cipherbird_benchmark/src/benchmark_table.dart';
import 'package:cipherbird_dart/cipherbird_dart.dart';

/// The 1.2.0 standards-track rows: ML-DSA and the hybrid signature,
/// X-Wing, HPKE over X-Wing, Suite v2 and Session v2. No comparison
/// package offers them, so the other columns stay empty.
Future<void> addBankRows(
  BenchmarkTable table,
  CipherBird lib, {
  required Uint8List kib,
}) async {
  const none = <Future<void> Function()?>[null, null, null];
  final dsa = lib.mlDsaKeygen(MlDsaLevel.level65);
  final dsaSig = lib.mlDsaSign(kib, dsa.secretKey, MlDsaLevel.level65);
  final hybrid = lib.hybridSigKeygen();
  final bob = lib.xwingKeygen();
  final alice = lib.hybridSigKeygen();
  final bobId = lib.hybridSigKeygen();
  await table.row('ML-DSA-65 sign, 1 KiB', [
    () async => lib.mlDsaSign(kib, dsa.secretKey, MlDsaLevel.level65),
    ...none,
  ]);
  await table.row('ML-DSA-65 verify, 1 KiB', [
    () async => lib.mlDsaVerify(kib, dsaSig, dsa.publicKey, MlDsaLevel.level65),
    ...none,
  ]);
  await table.row('Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB', [
    () async => lib.hybridSigVerify(
      kib,
      lib.hybridSigSign(kib, hybrid.secretKey),
      hybrid.publicKey,
    ),
    ...none,
  ]);
  await table.row('X-Wing keygen + encapsulate + decapsulate', [
    () async {
      final kp = lib.xwingKeygen();
      final (ct, _) = lib.xwingEncapsulate(kp.publicKey);
      lib.xwingDecapsulate(ct, kp.secretKey);
    },
    ...none,
  ]);
  await table.row('HPKE X-Wing seal + open, 1 KiB', [
    () async => hpkeRoundTrip(lib, bob, kib),
    ...none,
  ]);
  await table.row('Suite v2 seal + open, 1 KiB', [
    () async => lib.suite2Open(
      lib.suite2Seal(kib, bob.publicKey, alice.secretKey),
      bob.secretKey,
      bob.publicKey,
      alice.publicKey,
    ),
    ...none,
  ]);
  await table.row('Session v2 handshake (prekey, initiate, accept)', [
    () async => sessionHandshake(lib, alice, bobId),
    ...none,
  ]);
  final (a, b) = sessionHandshake(lib, alice, bobId);
  await table.row('Session v2 message encrypt + decrypt, 1 KiB', [
    () async => b.decrypt(a.encrypt(kib)),
    ...none,
  ]);
  a.close();
  b.close();
}
