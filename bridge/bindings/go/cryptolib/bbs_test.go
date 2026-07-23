package cryptolib

import (
	"bytes"
	"testing"
)

var bbsMsgs = []string{
	"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
	"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
	"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
	"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
	"496694774c5604ab1b2544eababcf0f53278ff50",
	"515ae153e22aae04ad16f759e07237b4",
	"d183ddc6e2665aa4e2f088af",
	"ac55fb33a75909ed",
	"96012096",
	"",
}

// Official fixtures (BLS12-381-SHA-256).
func TestBbsFixtures(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	sk := mustHex(t, "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc")
	pk := mustHex(t, "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c")
	header := mustHex(t, "11223344556677889900aabbccddeeff")

	got, err := BbsSkToPk(sk)
	if err != nil || !bytes.Equal(got, pk) {
		t.Fatalf("sk_to_pk mismatch: %v", err)
	}

	var msgs [][]byte
	for _, m := range bbsMsgs {
		msgs = append(msgs, mustHex(t, m))
	}
	sig, err := BbsSign(sk, pk, header, msgs)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "8339b285a4acd89dec7777c09543a43e3cc60684b0a6f8ab335da4825c96e1463e28f8c5f4fd0641d19cec5920d3a8ff4bedb6c9691454597bbd298288abed3632078557b2ace7d44caed846e1a0a1e8")
	if !bytes.Equal(sig, want) {
		t.Fatalf("signature mismatch: %x", sig)
	}
	if !BbsVerify(pk, sig, header, msgs) {
		t.Fatal("verify failed")
	}
}

func TestBbsSelectiveDisclosure(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	kp, err := BbsKeygen(mustHex(t, "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579"), nil)
	if err != nil {
		t.Fatal(err)
	}
	header := mustHex(t, "11223344556677889900aabbccddeeff")
	ph := mustHex(t, "aabbcc")
	var msgs [][]byte
	for _, m := range bbsMsgs {
		msgs = append(msgs, mustHex(t, m))
	}
	sig, err := BbsSign(kp.Secret, kp.Public, header, msgs)
	if err != nil {
		t.Fatal(err)
	}
	if !BbsVerify(kp.Public, sig, header, msgs) {
		t.Fatal("verify failed")
	}
	disclosed := []uint64{0, 3, 7}
	proof, err := BbsProofGen(kp.Public, sig, header, ph, msgs, disclosed)
	if err != nil {
		t.Fatal(err)
	}
	revealed := [][]byte{msgs[0], msgs[3], msgs[7]}
	if !BbsProofVerify(kp.Public, proof, header, ph, revealed, disclosed) {
		t.Fatal("proof verify failed")
	}
	// Wrong revealed message must fail.
	wrong := append([]byte(nil), msgs[3]...)
	wrong[0] ^= 1
	if BbsProofVerify(kp.Public, proof, header, ph, [][]byte{msgs[0], wrong, msgs[7]}, disclosed) {
		t.Fatal("proof accepted a wrong revealed message")
	}
}
