package cryptolib

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func noisePPM(w, h int, seed uint32) []byte {
	head := []byte("P6\n" + itoa(w) + " " + itoa(h) + "\n255\n")
	body := make([]byte, w*h*3)
	s := seed
	if s == 0 {
		s = 1
	}
	for i := range body {
		s ^= s << 13
		s ^= s >> 17
		s ^= s << 5
		body[i] = byte(s)
	}
	return append(head, body...)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// Keep Argon2id cheap so the suite stays fast.
func cheap(r *Recipe) *Recipe { return r.Argon2Cost(1, 8*1024*1024) }

func TestSecurityProfileMaximum(t *testing.T) {
	p := ProfileMaximum
	if p.MlKemLevel() != MlKem1024 || p.MlDsaLevel() != MlDsa87 {
		t.Fatal("maximum must use the category-5 parameter sets")
	}
	if p.SlhDsaLevel() != SlhDsaSmall256 || p.SlhDsaHash() != SlhDsaSHAKE {
		t.Fatal("maximum must use SLH-DSA-256s/SHAKE")
	}
	if p.SealedTier() != Fortress || p.KdfPreset() != KdfSensitive {
		t.Fatal("maximum must use the Fortress tier and the sensitive KDF")
	}
	c := p.Cascade()
	if len(c) != 3 || c[len(c)-1] != LayerCommitting {
		t.Fatal("maximum cascade must be three layers ending key-committing")
	}
	if ProfileBalanced.Argon2Memory() >= p.Argon2Memory() {
		t.Fatal("profiles must be ordered by cost")
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

func TestRecipeFailsClosed(t *testing.T) {
	secret := []byte("fail closed")
	key, _ := RandomBytes(32)
	r := NewRecipe(ProfileHigh).WithKey(key)

	env, _ := r.Seal(secret)
	tampered := append([]byte(nil), env...)
	tampered[len(tampered)-1] ^= 1
	if _, err := r.Open(tampered); err == nil {
		t.Fatal("a flipped ciphertext byte must be rejected")
	}

	hdr := append([]byte(nil), env...)
	hdr[7] = 1 // claim one layer instead of two
	if _, err := r.Open(hdr); err == nil {
		t.Fatal("a tampered header must be rejected — the descriptor is AAD")
	}

	salted := append([]byte(nil), env...)
	salted[10] ^= 0xFF
	if _, err := r.Open(salted); err == nil {
		t.Fatal("a tampered salt must be rejected")
	}

	other, _ := RandomBytes(32)
	if _, err := NewRecipe(ProfileHigh).WithKey(other).Open(env); err == nil {
		t.Fatal("a wrong key must be rejected")
	}
	if _, err := r.Open([]byte("not an envelope at all")); err == nil {
		t.Fatal("foreign bytes must not be mistaken for an envelope")
	}
	if _, err := NewRecipe(ProfileBalanced).WithKey(make([]byte, 31)).Seal(secret); err == nil {
		t.Fatal("a short key must be refused")
	}
	if _, err := NewRecipe(ProfileBalanced).WithLayers(nil).Seal(secret); err == nil {
		t.Fatal("an empty layer list must be refused")
	}
}

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
