package cryptolib

import (
	"bytes"
	"testing"
)

// RFC 9381 Appendix B.3 — ECVRF-EDWARDS25519-SHA512-TAI.
func TestEcvrfRFC9381(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ sk, pk, alpha, pi, beta string }{
		{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
			"8657106690b5526245a92b003bb079ccd1a92130477671f6fc01ad16f26f723f26f8a57ccaed74ee1b190bed1f479d9727d2d0f9b005a6e456a35d4fb0daab1268a1b0db10836d9826a528ca76567805",
			"90cf1df3b703cce59e2a35b925d411164068269d7b2d29f3301c03dd757876ff66b71dda49d2de59d03450451af026798e8f81cd2e333de5cdf4f3e140fdd8ae"},
		{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
			"f3141cd382dc42909d19ec5110469e4feae18300e94f304590abdced48aed5933bf0864a62558b3ed7f2fea45c92a465301b3bbf5e3e54ddf2d935be3b67926da3ef39226bbc355bdc9850112c8f4b02",
			"eb4440665d3891d668e7e0fcaf587f1b4bd7fbfe99d0eb2211ccec90496310eb5e33821bc613efb94db5e5b54c70a848a0bef4553a41befc57663b56373a5031"},
	}
	for _, c := range cases {
		sk, pk, alpha := mustHex(t, c.sk), mustHex(t, c.pk), mustHex(t, c.alpha)
		got, err := EcvrfPublicKey(sk)
		if err != nil || !bytes.Equal(got, pk) {
			t.Fatalf("public key mismatch: %x %v", got, err)
		}
		pi, err := EcvrfProve(sk, alpha)
		if err != nil || !bytes.Equal(pi, mustHex(t, c.pi)) {
			t.Fatalf("prove mismatch: %x %v", pi, err)
		}
		beta, err := EcvrfProofToHash(pi)
		if err != nil || !bytes.Equal(beta, mustHex(t, c.beta)) {
			t.Fatalf("proof_to_hash mismatch: %x %v", beta, err)
		}
		vb, err := EcvrfVerify(pk, alpha, pi)
		if err != nil || !bytes.Equal(vb, mustHex(t, c.beta)) {
			t.Fatalf("verify mismatch: %x %v", vb, err)
		}
	}
}

func TestEcvrfEndToEnd(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	kp := EcvrfKeygen()
	alpha := []byte("beacon round 42")
	pi, err := EcvrfProve(kp.Secret, alpha)
	if err != nil {
		t.Fatal(err)
	}
	beta, err := EcvrfVerify(kp.Public, alpha, pi)
	if err != nil || len(beta) != 64 {
		t.Fatalf("verify failed: %v", err)
	}
	// Deterministic: same input → same proof.
	pi2, _ := EcvrfProve(kp.Secret, alpha)
	if !bytes.Equal(pi, pi2) {
		t.Fatal("VRF not deterministic")
	}
	// Tampered proof rejected.
	bad := append([]byte(nil), pi...)
	bad[70] ^= 1
	if _, err := EcvrfVerify(kp.Public, alpha, bad); err == nil {
		t.Fatal("tampered proof accepted")
	}
	// Wrong key rejected.
	other := EcvrfKeygen()
	if _, err := EcvrfVerify(other.Public, alpha, pi); err == nil {
		t.Fatal("wrong key accepted")
	}
}
