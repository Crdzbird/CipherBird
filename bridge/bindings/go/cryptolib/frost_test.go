package cryptolib

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// RFC 9591 §C.1 — FROST(Ed25519, SHA-512) official test vectors.
func TestFrostRFC9591(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	gpk := mustHex(t, "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673")
	msg := mustHex(t, "74657374")
	s1 := mustHex(t, "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509")
	s3 := mustHex(t, "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02")
	h1 := mustHex(t, "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407")
	b1 := mustHex(t, "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301")
	h3 := mustHex(t, "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e")
	b3 := mustHex(t, "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d")
	hc1 := mustHex(t, "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3")
	bc1 := mustHex(t, "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932")
	hc3 := mustHex(t, "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91")
	bc3 := mustHex(t, "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552")
	ss1 := mustHex(t, "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603")
	ss3 := mustHex(t, "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007")
	wantSig := mustHex(t, "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"+
		"bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b")

	// Commitments derived from the vector nonces must match the vector commitments.
	_, c1, err := FrostCommitWithNonces(1, h1, b1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c1.Hiding, hc1) || !bytes.Equal(c1.Binding, bc1) {
		t.Fatal("commitment 1 mismatch")
	}
	_, c3, err := FrostCommitWithNonces(3, h3, b3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c3.Hiding, hc3) || !bytes.Equal(c3.Binding, bc3) {
		t.Fatal("commitment 3 mismatch")
	}

	cs := []FrostCommitment{c1, c3}

	// Signature shares must match the RFC exactly.
	got1, err := FrostSign(1, s1, gpk, FrostNonces{Hiding: h1, Binding: b1}, msg, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got1, ss1) {
		t.Fatalf("share 1: got %x", got1)
	}
	got3, err := FrostSign(3, s3, gpk, FrostNonces{Hiding: h3, Binding: b3}, msg, cs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got3, ss3) {
		t.Fatalf("share 3: got %x", got3)
	}

	// Aggregate must reproduce the RFC signature and verify as Ed25519.
	sig, err := FrostAggregate(gpk, msg, cs, [][]byte{ss1, ss3})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, wantSig) {
		t.Fatalf("aggregate: got %x", sig)
	}
	if !FrostVerify(msg, sig, gpk) {
		t.Fatal("verify failed")
	}
	if FrostVerify(mustHex(t, "74657375"), sig, gpk) {
		t.Fatal("verify accepted wrong message")
	}
}

// End-to-end with freshly generated keys: any 3-of-5 subset signs and verifies.
func TestFrostEndToEnd(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	kg, err := FrostKeygen(5, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(kg.SecretShares) != 5 || len(kg.PublicShares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(kg.SecretShares))
	}
	msg := []byte("threshold-signed payload")

	// Signers 1, 2, 4  → 0-based share indices 0, 1, 3.
	idx := []int{0, 1, 3}
	var cs []FrostCommitment
	var nonces []FrostNonces
	for _, i := range idx {
		n, c, err := FrostCommit(kg.SecretShares[i], uint16(i+1))
		if err != nil {
			t.Fatal(err)
		}
		nonces = append(nonces, n)
		cs = append(cs, c)
	}
	var shares [][]byte
	for k, i := range idx {
		s, err := FrostSign(uint16(i+1), kg.SecretShares[i], kg.GroupPublicKey, nonces[k], msg, cs)
		if err != nil {
			t.Fatal(err)
		}
		if !FrostVerifyShare(uint16(i+1), kg.PublicShares[i], s, cs[k], kg.GroupPublicKey, msg, cs) {
			t.Fatalf("share %d failed per-share verify", i+1)
		}
		shares = append(shares, s)
	}
	sig, err := FrostAggregate(kg.GroupPublicKey, msg, cs, shares)
	if err != nil {
		t.Fatal(err)
	}
	if !FrostVerify(msg, sig, kg.GroupPublicKey) {
		t.Fatal("e2e verify failed")
	}
	// A wrong public share must fail per-share verification.
	if FrostVerifyShare(uint16(idx[0]+1), kg.PublicShares[idx[1]], shares[0], cs[0], kg.GroupPublicKey, msg, cs) {
		t.Fatal("per-share verify accepted a wrong public share")
	}
}
