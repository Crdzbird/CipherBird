package cryptolib

import (
	"bytes"
	"testing"
)

// End-to-end BBS pseudonym/blind flow through the C ABI: commit(prover_nym) ->
// blind-sign -> finalize -> pseudonym -> proof gen -> proof verify = true.
func TestBbsPseudonymRoundTrip(t *testing.T) {
	sk := mustHex(t, "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
	pk := mustHex(t, "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c")
	header := mustHex(t, "11223344556677889900aabbccddeeff")
	ph := mustHex(t, "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501")
	ctx := mustHex(t, "bbb4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a")
	entropy := mustHex(t, "3d40961fce6c09eec24a371322732932503b458d7a4cf7891bdaa765b30027c5")
	proverNym := mustHex(t, "1234000000000000000000000000000000000000000000000000000000000000")

	signer := [][]byte{{0xaa}, {0xbb, 0xbb}}
	committed := [][]byte{{0xcc, 0xcc, 0xcc}, {0xdd}}
	nyms := [][]byte{proverNym}

	cwp, blind, err := BbsCommitWithNym(committed, nyms)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	sig, err := BbsBlindSignWithNym(sk, pk, cwp, header, signer, entropy, 1)
	if err != nil {
		t.Fatalf("blind_sign: %v", err)
	}
	nymSecrets, err := BbsFinalizeNymSecrets(nyms, entropy)
	if err != nil || len(nymSecrets) != 32 {
		t.Fatalf("finalize: %v len=%d", err, len(nymSecrets))
	}
	ns := [][]byte{nymSecrets}

	proof, pseudonym, err := BbsProofGenWithPseudonym(pk, sig, header, ph, ctx,
		signer, committed, blind, ns, []uint64{0, 1}, []uint64{0, 1})
	if err != nil {
		t.Fatalf("proof_gen: %v", err)
	}
	// Pseudonym from proof gen matches CalculatePseudonym.
	p2, _ := BbsCalculatePseudonym(ctx, ns)
	if !bytes.Equal(pseudonym, p2) {
		t.Fatal("pseudonym mismatch vs calculate_pseudonym")
	}

	// Verify: all disclosed; combined indexes [0,1, 3,4].
	dm := [][]byte{{0xaa}, {0xbb, 0xbb}, {0xcc, 0xcc, 0xcc}, {0xdd}}
	if !BbsProofVerifyWithPseudonym(pk, proof, header, ph, ctx, pseudonym, 2, 1, dm, []uint64{0, 1, 3, 4}) {
		t.Fatal("proof did not verify")
	}
	// Wrong context fails.
	badctx := mustHex(t, "aab4750cdce6d2122bb4c4f039b6ad5a79f028eb448013a38636a95d63af360a")
	if BbsProofVerifyWithPseudonym(pk, proof, header, ph, badctx, pseudonym, 2, 1, dm, []uint64{0, 1, 3, 4}) {
		t.Fatal("wrong-context proof should not verify")
	}
}

// Standalone blind issuance (no pseudonyms): commit → blind_sign → verify.
func TestBbsBlindIssuanceRoundTrip(t *testing.T) {
	sk := mustHex(t, "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
	pk, err := BbsSkToPk(sk)
	if err != nil {
		t.Fatalf("sk_to_pk: %v", err)
	}
	header := mustHex(t, "11223344556677889900aabbccddeeff")
	signer := [][]byte{[]byte("age>=18"), []byte("region=EU")}
	committed := [][]byte{[]byte("ssn=123-45-6789"), []byte("dob=1990-01-01")}

	cwp, blind, err := BbsBlindCommit(committed)
	if err != nil || len(blind) != 32 {
		t.Fatalf("blind_commit: %v len=%d", err, len(blind))
	}
	sig, err := BbsBlindSign(sk, pk, cwp, header, signer)
	if err != nil || len(sig) != 80 {
		t.Fatalf("blind_sign: %v len=%d", err, len(sig))
	}
	if !BbsVerifyBlindSign(pk, sig, header, signer, committed, blind) {
		t.Fatal("verify_blind_sign should accept")
	}
	// Wrong blind and wrong committed message both fail.
	badBlind := append([]byte(nil), blind...)
	badBlind[0] ^= 1
	if BbsVerifyBlindSign(pk, sig, header, signer, committed, badBlind) {
		t.Fatal("wrong secret_prover_blind should fail")
	}
	if BbsVerifyBlindSign(pk, sig, header, signer, [][]byte{[]byte("ssn=000"), []byte("dob=1990-01-01")}, blind) {
		t.Fatal("wrong committed message should fail")
	}
}
