//go:build !cryptolib_bank

package cryptolib

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecipeFecAndCarrier(t *testing.T) {
	secret := []byte("survives a flipped bit")
	key, _ := RandomBytes(32)

	r := NewRecipe(ProfileBalanced).WithKey(key).WithFec(FecRepetition3)
	env, err := r.Seal(secret)
	if err != nil {
		t.Fatalf("fec seal: %v", err)
	}
	env[len(env)/2] ^= 1
	if got, err := r.Open(env); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("fec must correct a single flip: %v", err)
	}

	dir := t.TempDir()
	cover := filepath.Join(dir, "cover.ppm")
	out := filepath.Join(dir, "carrier.ppm")
	if err := os.WriteFile(cover, noisePPM(256, 256, 0x0FF1CE), 0o600); err != nil {
		t.Fatal(err)
	}
	cr := cheap(MaximumSecurity().WithPassphrase("a long passphrase here"))
	if err := cr.SealIntoCarrier(secret, cover, out); err != nil {
		t.Fatalf("seal into carrier: %v", err)
	}
	if got, err := cr.OpenFromCarrier(out); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("open from carrier: %v", err)
	}
	if insp, err := StegoInspect(out); err != nil || !insp.Parses {
		t.Fatal("the carrier must still be a valid image")
	}
}

func TestRecipeRoundTrips(t *testing.T) {
	secret := []byte("the treaty text nobody may read")

	key, _ := RandomBytes(32)
	r := NewRecipe(ProfileHigh).WithKey(key)
	env, err := r.Seal(secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := r.Open(env)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("raw key round-trip: %v", err)
	}

	pr := cheap(MaximumSecurity().WithPassphrase("correct horse battery staple"))
	penv, err := pr.Seal(secret)
	if err != nil {
		t.Fatalf("passphrase seal: %v", err)
	}
	if got, err := pr.Open(penv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("passphrase round-trip: %v", err)
	}

	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.ppm")
	if err := os.WriteFile(keyFile, noisePPM(96, 96, 0x5EED), 0o600); err != nil {
		t.Fatal(err)
	}
	// A second recipe object must reopen the first one's envelope: the key-file
	// source has to use the deterministic entropy path.
	fenv, err := NewRecipe(ProfileBalanced).WithKeyFile(keyFile).Seal(secret)
	if err != nil {
		t.Fatalf("key file seal: %v", err)
	}
	if got, err := NewRecipe(ProfileBalanced).WithKeyFile(keyFile).Open(fenv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("key file round-trip: %v", err)
	}
}

func TestRecipeComposition(t *testing.T) {
	secret := []byte("layered")
	key, _ := RandomBytes(32)

	one, _ := NewRecipe(ProfileBalanced).WithKey(key).
		WithLayers([]ProtectionLayer{LayerXChaCha20Poly1305}).Seal(secret)
	three, _ := NewRecipe(ProfileBalanced).WithKey(key).
		WithLayers([]ProtectionLayer{LayerXChaCha20Poly1305, LayerAES256GCM}).
		AddLayer(LayerCommitting).Seal(secret)
	if len(three) <= len(one) {
		t.Fatal("each layer must add its own overhead")
	}

	mol := NewRecipe(ProfileBalanced).WithKey(key).
		WithLayers([]ProtectionLayer{LayerMolecular})
	menv, err := mol.Seal(secret)
	if err != nil {
		t.Fatalf("molecular layer: %v", err)
	}
	if got, _ := mol.Open(menv); !bytes.Equal(got, secret) {
		t.Fatal("molecular layer round-trip")
	}

	id := Ed25519Keygen()
	signed := NewRecipe(ProfileHigh).WithKey(key).
		SignedBy(id.Secret, SigEd25519).VerifiedBy(id.Public)
	senv, err := signed.Seal(secret)
	if err != nil {
		t.Fatalf("signed seal: %v", err)
	}
	if got, err := signed.Open(senv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("signed round-trip: %v", err)
	}

	hid := HybridSigKeygen()
	hy := NewRecipe(ProfileBalanced).WithKey(key).
		SignedBy(hid.Secret, SigHybrid).VerifiedBy(hid.Public)
	henv, _ := hy.Seal(secret)
	if got, err := hy.Open(henv); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("hybrid signed round-trip: %v", err)
	}

	// Wrong signer, and a signed envelope opened without a verification key.
	impostor := Ed25519Keygen()
	if _, err := NewRecipe(ProfileHigh).WithKey(key).VerifiedBy(impostor.Public).Open(senv); err == nil {
		t.Fatal("a wrong signer must be rejected")
	}
	if _, err := NewRecipe(ProfileHigh).WithKey(key).Open(senv); err == nil {
		t.Fatal("a signed envelope must not open without a verification key")
	}
}
