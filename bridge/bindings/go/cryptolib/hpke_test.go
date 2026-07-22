package cryptolib

import (
	"bytes"
	"testing"
)

// RFC 9180 §A.2 — DHKEM(X25519,HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305.
func TestHpkeRFC9180Base(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	skRm := mustHex(t, "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
	pkRm := mustHex(t, "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a")
	ikmR := mustHex(t, "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df")
	enc := mustHex(t, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")
	info := mustHex(t, "4f6465206f6e2061204772656369616e2055726e")
	pt := mustHex(t, "4265617574792069732074727574682c20747275746820626561757479")
	aad0 := mustHex(t, "436f756e742d30")
	ct0 := mustHex(t, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28")
	exp0 := mustHex(t, "4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e")

	// DeriveKeyPair reproduces the vector receiver key pair.
	dk := HpkeDeriveKeyPair(ikmR)
	if !bytes.Equal(dk.Secret, skRm) || !bytes.Equal(dk.Public, pkRm) {
		t.Fatal("DeriveKeyPair mismatch")
	}

	r, err := HpkeSetupR(HpkeKdfSha256, HpkeAeadChaCha20Poly1305, HpkeModeBase, enc, skRm, info, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := r.Open(aad0, ct0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("open mismatch: %x", got)
	}
	ex, err := r.Export(nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ex, exp0) {
		t.Fatalf("export mismatch: %x", ex)
	}
}

// End-to-end across modes and AEADs with fresh keys.
func TestHpkeEndToEnd(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	info := []byte("app-info")
	aad := []byte("meta")
	pt := []byte("top-secret payload")

	// Base + AES-256-GCM single-shot.
	bob := HpkeKeygen()
	enc, ct, err := HpkeSealBase(HpkeKdfSha256, HpkeAeadAes256Gcm, bob.Public, info, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	out, err := HpkeOpenBase(HpkeKdfSha256, HpkeAeadAes256Gcm, enc, bob.Secret, info, aad, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, pt) {
		t.Fatal("base round-trip mismatch")
	}
	// Tampered ciphertext must be rejected.
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	if _, err := HpkeOpenBase(HpkeKdfSha256, HpkeAeadAes256Gcm, enc, bob.Secret, info, aad, bad); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}

	// Auth mode, HKDF-SHA512, multi-message + matching export.
	alice := HpkeKeygen()
	s, err := HpkeSetupS(HpkeKdfSha512, HpkeAeadChaCha20Poly1305, HpkeModeAuth, bob.Public, info, nil, nil, alice.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Context.Close()
	rr, err := HpkeSetupR(HpkeKdfSha512, HpkeAeadChaCha20Poly1305, HpkeModeAuth, s.Enc, bob.Secret, info, nil, nil, alice.Public)
	if err != nil {
		t.Fatal(err)
	}
	defer rr.Close()
	for i := 0; i < 4; i++ {
		msg := []byte{'m', 's', 'g', byte('0' + i)}
		c, err := s.Context.Seal(nil, msg)
		if err != nil {
			t.Fatal(err)
		}
		o, err := rr.Open(nil, c)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(o, msg) {
			t.Fatalf("auth message %d mismatch", i)
		}
	}
	es, _ := s.Context.Export([]byte("lab"), 32)
	er, _ := rr.Export([]byte("lab"), 32)
	if !bytes.Equal(es, er) {
		t.Fatal("exporter secrets differ across the channel")
	}
}
