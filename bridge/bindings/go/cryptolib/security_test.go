package cryptolib

import (
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
