// BBS per-verifier pseudonyms + blind issuance — verified against the host dylib.
// Run with: CRYPTOLIB_DYLIB=<path-to-libcryptolib_c.dylib> flutter test test/bbs_pseudonym_test.dart
import 'dart:typed_data';
import 'package:cipherbird_dart/cipherbird_dart.dart';
import 'package:test/test.dart';

Uint8List _hx(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

bool _eq(Uint8List a, Uint8List b) =>
    a.length == b.length &&
    () {
      for (var i = 0; i < a.length; i++) {
        if (a[i] != b[i]) return false;
      }
      return true;
    }();

void main() {
  final lib = CryptoLib.instance;

  final sk = _hx(
    '60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc',
  );
  final pk = _hx(
    'a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c',
  );
  final header = _hx('11223344556677889900aabbccddeeff');
  final ph = _hx(
    'bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501',
  );
  final ctx = _hx(
    'bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a',
  );
  final entropy = _hx(
    '3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5',
  );
  final proverNym = _hx(
    '1234000000000000000000000000000000000000000000000000000000000000',
  );

  final signer = [
    Uint8List.fromList([0xaa]),
    Uint8List.fromList([0xbb, 0xbb]),
  ];
  final committed = [
    Uint8List.fromList([0xcc, 0xcc, 0xcc]),
    Uint8List.fromList([0xdd]),
  ];
  final nyms = [proverNym];

  test(
    'pseudonym blind-issuance round-trip -> VALID; wrong context rejected',
    () {
      final (cwp, blind) = lib.bbsCommitWithNym(committed, nyms);
      expect(cwp, isNotEmpty);
      expect(blind.length, 32);

      final sig = lib.bbsBlindSignWithNym(
        sk,
        pk,
        cwp,
        header,
        signer,
        entropy,
        1,
      );
      expect(sig.length, 80);

      final nymSecrets = lib.bbsFinalizeNymSecrets(nyms, entropy);
      expect(nymSecrets.length, 32);
      final ns = [nymSecrets];

      final (proof, pseudonym) = lib.bbsProofGenWithPseudonym(
        pk,
        sig,
        header,
        ph,
        ctx,
        signer,
        committed,
        blind,
        ns,
        [0, 1],
        [0, 1],
      );
      expect(proof, isNotEmpty);
      expect(pseudonym.length, 48);
      expect(_eq(pseudonym, lib.bbsCalculatePseudonym(ctx, ns)), isTrue);

      final dm = [
        Uint8List.fromList([0xaa]),
        Uint8List.fromList([0xbb, 0xbb]),
        Uint8List.fromList([0xcc, 0xcc, 0xcc]),
        Uint8List.fromList([0xdd]),
      ];
      expect(
        lib.bbsProofVerifyWithPseudonym(
          pk,
          proof,
          header,
          ph,
          ctx,
          pseudonym,
          2,
          1,
          dm,
          [0, 1, 3, 4],
        ),
        isTrue,
      );

      final badctx = _hx(
        'aab4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a',
      );
      expect(
        lib.bbsProofVerifyWithPseudonym(
          pk,
          proof,
          header,
          ph,
          badctx,
          pseudonym,
          2,
          1,
          dm,
          [0, 1, 3, 4],
        ),
        isFalse,
      );
    },
  );

  test('standalone blind issuance: commit -> blind_sign -> verify', () {
    final skpk = lib.bbsSkToPk(sk);
    final signer2 = [
      Uint8List.fromList('age>=18'.codeUnits),
      Uint8List.fromList('region=EU'.codeUnits),
    ];
    final committed2 = [
      Uint8List.fromList('ssn=123'.codeUnits),
      Uint8List.fromList('dob=1990'.codeUnits),
    ];

    final (cwp, blind) = lib.bbsBlindCommit(committed2);
    expect(cwp, isNotEmpty);
    expect(blind.length, 32);

    final sig = lib.bbsBlindSign(sk, skpk, cwp, header, signer2);
    expect(sig.length, 80);
    expect(
      lib.bbsVerifyBlindSign(skpk, sig, header, signer2, committed2, blind),
      isTrue,
    );

    final badBlind = Uint8List.fromList(blind);
    badBlind[0] ^= 1;
    expect(
      lib.bbsVerifyBlindSign(skpk, sig, header, signer2, committed2, badBlind),
      isFalse,
    );
  });

  test('canonical scalar helpers: hash_to_scalar KAT + random_scalar', () {
    final msg = _hx(
      '9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02',
    );
    final dst = _hx(
      '4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4832535f',
    );
    final scalar = lib.bbsHashToScalar(msg, dst);
    expect(
      _eq(
        scalar,
        _hx('0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c'),
      ),
      isTrue,
    );
    final r1 = lib.bbsRandomScalar(), r2 = lib.bbsRandomScalar();
    expect(r1.length, 32);
    expect(_eq(r1, r2), isFalse);
  });
}
