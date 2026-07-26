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

func TestStegoAnalysis(t *testing.T) {
	dir := t.TempDir()
	cover := filepath.Join(dir, "cover.ppm")
	stego := filepath.Join(dir, "stego.ppm")
	writeNoisePPM(t, cover, 128, 128, 0x77)

	// Validity: a real PPM parses; its content matches the .ppm extension.
	fi, err := StegoInspect(cover)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !fi.Parses || !fi.ExtMatches || fi.Width != 128 {
		t.Fatalf("unexpected inspection: %+v", fi)
	}

	// Tamper detection via stored digest.
	d1, err := StegoContentDigest(cover)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	d1b, _ := StegoContentDigest(cover)
	if !bytes.Equal(d1, d1b) {
		t.Fatal("digest not stable")
	}
	if err := os.WriteFile(cover, append(mustRead(t, cover), 0x00), 0o600); err != nil {
		t.Fatal(err)
	}
	d2, _ := StegoContentDigest(cover)
	if bytes.Equal(d1, d2) {
		t.Fatal("digest should change after tamper")
	}

	// Hidden-data probe: an unkeyed cryptolib embed is detected definitively.
	writeNoisePPM(t, cover, 128, 128, 0x77)
	if err := StegoEmbed(cover, []byte("hi there"), stego); err != nil {
		t.Fatalf("embed: %v", err)
	}
	rep, err := StegoDetectHidden(stego)
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if !rep.CryptolibPayload {
		t.Fatal("expected cryptolib payload to be detected")
	}
	if rep.Note == "" {
		t.Fatal("expected an honesty note")
	}
}

func TestImageFactorSeal(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "ref.ppm")
	cover := filepath.Join(dir, "cover.ppm")
	out := filepath.Join(dir, "out.ppm")
	writeNoisePPM(t, img, 64, 64, 0xFEED)
	writeNoisePPM(t, cover, 256, 256, 0xCAFE)

	seed := bytes.Repeat([]byte{0x42}, 32)
	msg := []byte("image is the second factor")
	if err := ImageFactorSeal(seed, img, msg, nil, cover, out); err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := ImageFactorOpen(seed, img, nil, out)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open mismatch: %v %q", err, got)
	}
	// Wrong reference image → fail.
	other := filepath.Join(dir, "other.ppm")
	writeNoisePPM(t, other, 64, 64, 0xBEEF)
	if _, err := ImageFactorOpen(seed, other, nil, out); err == nil {
		t.Fatal("expected wrong-image open to fail")
	}
}

func TestHpkeStegoSeal(t *testing.T) {
	dir := t.TempDir()
	cover := filepath.Join(dir, "cover.ppm")
	out := filepath.Join(dir, "out.ppm")
	writeNoisePPM(t, cover, 256, 256, 0x1234)

	recip := HpkeKeygen()
	info := []byte("session")
	msg := []byte("one session keys both cipher and cover")
	enc, err := HpkeStegoSeal(recip.Public, msg, nil, info, cover, out)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := HpkeStegoOpen(recip.Secret, enc, nil, info, out)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("open mismatch: %v %q", err, got)
	}
	// Wrong recipient secret → fail.
	mallory := HpkeKeygen()
	if _, err := HpkeStegoOpen(mallory.Secret, enc, nil, info, out); err == nil {
		t.Fatal("expected wrong-recipient open to fail")
	}
}

func TestDrbgHandle(t *testing.T) {
	seed := bytes.Repeat([]byte{0x01}, 32)
	d1, err := NewDrbg(seed, nil, []byte("beacon"))
	if err != nil {
		t.Fatalf("instantiate: %v", err)
	}
	defer d1.Close()
	a, _ := d1.Generate(64, nil)
	b, _ := d1.Generate(64, nil)
	if bytes.Equal(a, b) {
		t.Fatal("successive DRBG blocks must differ")
	}
	// Same seed+perso reproduces the stream.
	d2, _ := NewDrbg(seed, nil, []byte("beacon"))
	defer d2.Close()
	a2, _ := d2.Generate(64, nil)
	if !bytes.Equal(a, a2) {
		t.Fatal("same seed must reproduce the first block")
	}
	// Too-little entropy is rejected.
	if _, err := NewDrbg([]byte{1, 2, 3}, nil, nil); err == nil {
		t.Fatal("expected short-entropy instantiate to fail")
	}
}

func TestFortunaHandle(t *testing.T) {
	f := NewFortuna()
	defer f.Close()
	if _, err := f.Generate(32); err == nil {
		t.Fatal("expected unseeded generate to fail")
	}
	for i := 0; i < 40; i++ {
		f.AddEntropy(byte(i&7), bytes.Repeat([]byte{byte(i)}, 16))
	}
	f.Reseed()
	if f.ReseedCount() < 1 {
		t.Fatal("reseed count should advance")
	}
	out, err := f.Generate(64)
	if err != nil || len(out) != 64 {
		t.Fatalf("generate: %v len=%d", err, len(out))
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
