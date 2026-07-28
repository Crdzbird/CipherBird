// Verifies the BBS per-verifier pseudonym / blind-issuance bindings via dart:ffi.
//   dart run bin/bbs_pseudonym_verify.dart [path-to-libcryptolib_c.dylib]
// Exits non-zero on any failure.
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptolib_dart/cryptolib_ffi.dart';

int _failures = 0;
void check(bool ok, String label) {
  stdout.writeln('${ok ? "  ok  " : " FAIL "} $label');
  if (!ok) _failures++;
}

Uint8List hx(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

bool eq(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

void main(List<String> args) {
  final path =
      args.isNotEmpty ? args[0] : 'build/release/libcryptolib_c.dylib';
  final lib = CryptoLib.load(path);
  lib.init();

  final sk = hx('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc');
  final pk = hx('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c');
  final header = hx('11223344556677889900aabbccddeeff');
  final ph = hx('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501');
  final ctx = hx('bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a');
  final entropy = hx('3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5');
  final proverNym = hx('1234000000000000000000000000000000000000000000000000000000000000');

  final signer = [Uint8List.fromList([0xaa]), Uint8List.fromList([0xbb, 0xbb])];
  final committed = [Uint8List.fromList([0xcc, 0xcc, 0xcc]), Uint8List.fromList([0xdd])];
  final nyms = [proverNym];

  final (cwp, blind) = lib.bbsCommitWithNym(committed, nyms);
  check(cwp.isNotEmpty && blind.length == 32, 'commit_with_nym');

  final sig = lib.bbsBlindSignWithNym(sk, pk, cwp, header, signer, entropy, 1);
  check(sig.length == 80, 'blind_sign_with_nym (80-byte sig)');

  final nymSecrets = lib.bbsFinalizeNymSecrets(nyms, entropy);
  check(nymSecrets.length == 32, 'finalize_nym_secrets');
  final ns = [nymSecrets];

  final (proof, pseudonym) = lib.bbsProofGenWithPseudonym(
      pk, sig, header, ph, ctx, signer, committed, blind, ns, [0, 1], [0, 1]);
  check(proof.isNotEmpty && pseudonym.length == 48, 'proof_gen_with_pseudonym');

  final p2 = lib.bbsCalculatePseudonym(ctx, ns);
  check(eq(pseudonym, p2), 'pseudonym matches calculate_pseudonym');

  final dm = [
    Uint8List.fromList([0xaa]),
    Uint8List.fromList([0xbb, 0xbb]),
    Uint8List.fromList([0xcc, 0xcc, 0xcc]),
    Uint8List.fromList([0xdd]),
  ];
  final ok = lib.bbsProofVerifyWithPseudonym(
      pk, proof, header, ph, ctx, pseudonym, 2, 1, dm, [0, 1, 3, 4]);
  check(ok, 'proof_verify_with_pseudonym = VALID');

  final badctx = hx('aab4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a');
  final bad = lib.bbsProofVerifyWithPseudonym(
      pk, proof, header, ph, badctx, pseudonym, 2, 1, dm, [0, 1, 3, 4]);
  check(!bad, 'wrong-context proof rejected');

  // ── Standalone blind issuance (no pseudonyms) ──────────────────────────────
  final signer2 = [Uint8List.fromList('age>=18'.codeUnits), Uint8List.fromList('region=EU'.codeUnits)];
  final committed2 = [Uint8List.fromList('ssn=123'.codeUnits), Uint8List.fromList('dob=1990'.codeUnits)];
  final skpk = lib.bbsSkToPk(sk);
  final (cwp2, blind2) = lib.bbsBlindCommit(committed2);
  check(cwp2.isNotEmpty && blind2.length == 32, 'blind_commit');
  final sig2 = lib.bbsBlindSign(sk, skpk, cwp2, header, signer2);
  check(sig2.length == 80, 'blind_sign (80-byte sig)');
  check(lib.bbsVerifyBlindSign(skpk, sig2, header, signer2, committed2, blind2), 'verify_blind_sign = VALID');
  final badBlind = Uint8List.fromList(blind2);
  badBlind[0] ^= 1;
  check(!lib.bbsVerifyBlindSign(skpk, sig2, header, signer2, committed2, badBlind), 'wrong blind rejected');

  stdout.writeln(_failures == 0 ? '\nALL PASS' : '\n$_failures FAILURE(S)');
  exit(_failures == 0 ? 0 : 1);
}
