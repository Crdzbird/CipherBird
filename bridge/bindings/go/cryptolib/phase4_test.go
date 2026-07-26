package cryptolib

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// writeNoisePPM writes a valid P6 PPM full of deterministic high-entropy noise —
// a valid stego carrier and (deterministic) MediaEntropy source.
func writeNoisePPM(t *testing.T, path string, w, h int, seed uint32) {
	t.Helper()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "P6\n%d %d\n255\n", w, h)
	s := seed
	if s == 0 {
		s = 1
	}
	for i := 0; i < w*h*3; i++ {
		s ^= s << 13
		s ^= s >> 17
		s ^= s << 5
		buf.WriteByte(byte(s))
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write ppm: %v", err)
	}
}

func TestKeyedStegoRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cover := filepath.Join(dir, "cover.ppm")
	out := filepath.Join(dir, "out.ppm")
	writeNoisePPM(t, cover, 256, 256, 0xC0FFEE)

	key := bytes.Repeat([]byte{0x5a}, 32)
	payload := []byte("keyed stego through the Go binding")

	if err := StegoEmbedKeyed(cover, payload, out, key); err != nil {
		t.Fatalf("embed: %v", err)
	}
	got, err := StegoExtractKeyed(out, key)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("round-trip mismatch: %q != %q", got, payload)
	}
	// Wrong key fails.
	if _, err := StegoExtractKeyed(out, bytes.Repeat([]byte{0x99}, 32)); err == nil {
		t.Fatal("expected wrong-key extraction to fail")
	}
}

func TestStegoEmbedEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cover := filepath.Join(dir, "cover.ppm")
	out := filepath.Join(dir, "out.ppm")
	writeNoisePPM(t, cover, 256, 256, 0xBEEF)

	key := bytes.Repeat([]byte{0x11}, 32)
	secret := []byte("never in the clear")
	if err := StegoEmbedEncrypted(cover, secret, out, key); err != nil {
		t.Fatalf("embed_encrypted: %v", err)
	}
	got, err := StegoExtractDecrypt(out, key)
	if err != nil {
		t.Fatalf("extract_decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("mismatch: %q != %q", got, secret)
	}
	if _, err := StegoExtractDecrypt(out, bytes.Repeat([]byte{0x22}, 32)); err == nil {
		t.Fatal("expected wrong-key decrypt to fail")
	}
}

func TestPhysicalSealRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyMedia := filepath.Join(dir, "key.ppm")
	cover := filepath.Join(dir, "cover.ppm")
	out := filepath.Join(dir, "out.ppm")
	writeNoisePPM(t, keyMedia, 64, 64, 0xABCDEF)
	writeNoisePPM(t, cover, 256, 256, 0x123456)

	msg := []byte("two-factor: the photo is the key")
	aad := []byte("go-ctx")
	if err := PhysicalSeal(keyMedia, msg, aad, cover, out); err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := PhysicalOpen(keyMedia, aad, out)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("mismatch: %q != %q", got, msg)
	}
	// Wrong AAD fails.
	if _, err := PhysicalOpen(keyMedia, []byte("wrong"), out); err == nil {
		t.Fatal("expected wrong-aad open to fail")
	}
}

func TestFecRoundTripWithErrors(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF}
	for _, s := range []FecScheme{FecRepetition3, FecRepetition5, FecHamming74} {
		enc, err := FecEncode(data, s)
		if err != nil {
			t.Fatalf("encode scheme %d: %v", s, err)
		}
		// Flip one bit in the first Hamming/repetition block — must be corrected.
		enc[0] ^= 0x40
		dec, err := FecDecode(enc, s, len(data))
		if err != nil {
			t.Fatalf("decode scheme %d: %v", s, err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("scheme %d did not correct a single flip: %x != %x", s, dec, data)
		}
	}
}
