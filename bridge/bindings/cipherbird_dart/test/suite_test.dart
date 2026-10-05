// Suite (one-call advanced combinations) — verified against the host dylib.
import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Future<void> main() async {
  await CipherBird.preload(runner: const CipherBirdInlineRunner());
  final lib = CipherBird.instance;
  final aad = Uint8List.fromList('suite/v1'.codeUnits);
  Uint8List B(String s) => Uint8List.fromList(s.codeUnits);
  bool eq(Uint8List a, Uint8List b) =>
      a.length == b.length &&
      () {
        for (var i = 0; i < a.length; i++) {
          if (a[i] != b[i]) return false;
        }
        return true;
      }();

  test('signed_pq: PQ confidentiality + authenticity round-trips', () {
    final bob = lib.hybridKemKeygen();
    final signer = lib.hybridSigKeygen();
    final pt = B('transfer 100 to acct #42');
    final env = lib.suiteSealSignedPq(
      pt,
      bob.publicKey,
      signer.secretKey,
      aad: aad,
    );
    final out = lib.suiteOpenSignedPq(
      env,
      bob.secretKey,
      signer.publicKey,
      aad: aad,
    );
    expect(eq(out, pt), isTrue);
  });

  test('signed_pq rejects a wrong signer', () {
    final bob = lib.hybridKemKeygen();
    final signer = lib.hybridSigKeygen();
    final impostor = lib.hybridSigKeygen();
    final env = lib.suiteSealSignedPq(
      B('x'),
      bob.publicKey,
      signer.secretKey,
      aad: aad,
    );
    expect(
      () => lib.suiteOpenSignedPq(
        env,
        bob.secretKey,
        impostor.publicKey,
        aad: aad,
      ),
      throwsA(anything),
    );
  });

  test('threshold 3-of-5: any quorum opens, below quorum fails', () {
    final (env, shares) = lib.suiteSealThreshold(
      B('board resolution'),
      5,
      3,
      aad: aad,
    );
    expect(shares.length, 5);
    final quorum = [shares[0], shares[2], shares[4]];
    expect(
      lib.suiteOpenThreshold(env, quorum, aad: aad),
      equals(B('board resolution')),
    );
    expect(
      () => lib.suiteOpenThreshold(env, [shares[0], shares[1]], aad: aad),
      throwsA(anything),
    );
  });

  test('evm_address derives 20 bytes', () {
    final w = lib.secp256k1Keygen();
    expect(lib.suiteEvmAddress(w.publicKey).length, 20);
  });
}
