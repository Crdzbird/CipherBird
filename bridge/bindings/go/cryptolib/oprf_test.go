package cryptolib

import (
	"bytes"
	"testing"
)

// RFC 9497 Appendix A.1.1 — OPRF(ristretto255, SHA-512), base mode.
func TestOprfRFC9497(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	seed := mustHex(t, "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3")
	info := mustHex(t, "74657374206b6579")
	kp, err := OprfDeriveKeyPair(seed, info)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.Secret, mustHex(t, "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e")) {
		t.Fatal("derived key mismatch")
	}
	input := mustHex(t, "00")
	blind := mustHex(t, "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706")

	b, err := OprfBlindWithScalar(input, blind)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b.BlindedElement, mustHex(t, "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c")) {
		t.Fatalf("blinded element mismatch: %x", b.BlindedElement)
	}
	ev, err := OprfBlindEvaluate(kp.Secret, b.BlindedElement)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ev, mustHex(t, "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e")) {
		t.Fatal("evaluation element mismatch")
	}
	out, err := OprfFinalize(input, blind, ev)
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6")
	if !bytes.Equal(out, want) {
		t.Fatalf("output mismatch: %x", out)
	}
	// Server one-shot matches.
	srv, err := OprfEvaluate(kp.Secret, input)
	if err != nil || !bytes.Equal(srv, want) {
		t.Fatal("server evaluate mismatch")
	}
}

func TestOprfObliviousFlow(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	kp, err := OprfDeriveKeyPair(mustHex(t, "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"), nil)
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("password")
	b, err := OprfBlindInput(input)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := OprfBlindEvaluate(kp.Secret, b.BlindedElement)
	out, _ := OprfFinalize(input, b.Blind, ev)
	srv, _ := OprfEvaluate(kp.Secret, input)
	if !bytes.Equal(out, srv) {
		t.Fatal("oblivious output != server evaluate")
	}
	// Re-blinding yields a different blinded element but the same output.
	b2, _ := OprfBlindInput(input)
	if bytes.Equal(b2.BlindedElement, b.BlindedElement) {
		t.Fatal("re-blind produced same blinded element")
	}
	ev2, _ := OprfBlindEvaluate(kp.Secret, b2.BlindedElement)
	out2, _ := OprfFinalize(input, b2.Blind, ev2)
	if !bytes.Equal(out2, out) {
		t.Fatal("re-blind produced different output")
	}
}
