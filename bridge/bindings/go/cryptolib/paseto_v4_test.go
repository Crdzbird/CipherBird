package cryptolib

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

var pasetoB64 = base64.RawURLEncoding.Strict()

func pasetoKey(t testing.TB, start byte) []byte {
	t.Helper()
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	return counting(32, start)
}

func TestPasetoV4LocalRoundTrip(t *testing.T) {
	k := pasetoKey(t, 0x70)
	cases := []struct {
		name          string
		payload, f, i []byte
	}{
		{"empty", nil, nil, nil},
		{"payload", []byte(`{"data":"x"}`), nil, nil},
		{"footer", []byte(`{"data":"x"}`), []byte(`{"kid":"a"}`), nil},
		{"implicit", []byte(`{"data":"x"}`), nil, []byte("ctx")},
		{"all", bytes.Repeat([]byte{0xff}, 1000), []byte("f"), []byte("i")},
		{"large", bytes.Repeat([]byte{0x5a}, 1<<20), bytes.Repeat([]byte{1}, 3000), []byte("i")},
	}
	for _, c := range cases {
		tok, err := PasetoV4LocalEncrypt(k, c.payload, c.f, c.i)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		dots := 2
		if len(c.f) > 0 {
			dots = 3
		}
		if !strings.HasPrefix(tok, "v4.local.") || strings.Count(tok, ".") != dots {
			t.Fatalf("%s: shape %.40q", c.name, tok)
		}
		got, err := PasetoV4LocalDecrypt(tok, k, c.f, c.i)
		if err != nil || !bytes.Equal(got, c.payload) || cap(got) != len(got) {
			t.Fatalf("%s: got %d bytes cap %d, %v", c.name, len(got), cap(got), err)
		}
	}
}

func TestPasetoV4LocalNonceIsFresh(t *testing.T) {
	k := pasetoKey(t, 0x70)
	a, _ := PasetoV4LocalEncrypt(k, []byte("m"), nil, nil)
	b, _ := PasetoV4LocalEncrypt(k, []byte("m"), nil, nil)
	if a == b {
		t.Fatal("two encryptions of the same message are equal")
	}
}

func TestPasetoV4LocalTamperEveryByte(t *testing.T) {
	k := pasetoKey(t, 0x70)
	f, i := []byte(`{"kid":"k"}`), []byte("bind")
	tok, err := PasetoV4LocalEncrypt(k, []byte(`{"exp":"2026-11-02T00:00:00Z"}`), f, i)
	if err != nil {
		t.Fatal(err)
	}
	for p := 0; p < len(tok); p++ {
		for _, bit := range []byte{0x01, 0x80} {
			b := []byte(tok)
			b[p] ^= bit
			if _, err := PasetoV4LocalDecrypt(string(b), k, f, i); !errors.Is(err, ErrPasetoInvalid) {
				t.Fatalf("token byte %d tampered: %v", p, err)
			}
		}
	}
	parts := strings.Split(tok[len("v4.local."):], ".")
	raw, err := pasetoB64.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	for p := range raw {
		r := append([]byte(nil), raw...)
		r[p] ^= 0x01
		forged := "v4.local." + pasetoB64.EncodeToString(r) + "." + parts[1]
		if _, err := PasetoV4LocalDecrypt(forged, k, f, i); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("decoded byte %d of %d tampered: %v", p, len(raw), err)
		}
	}
}

func TestPasetoV4LocalWrongContextFails(t *testing.T) {
	k, other := pasetoKey(t, 0x70), pasetoKey(t, 0x71)
	tok, err := PasetoV4LocalEncrypt(k, []byte("m"), []byte("f"), []byte("class=1"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func() error{
		"implicit":       func() error { _, err := PasetoV4LocalDecrypt(tok, k, []byte("f"), []byte("class=2")); return err },
		"no implicit":    func() error { _, err := PasetoV4LocalDecrypt(tok, k, []byte("f"), nil); return err },
		"footer":         func() error { _, err := PasetoV4LocalDecrypt(tok, k, []byte("g"), []byte("class=1")); return err },
		"missing footer": func() error { _, err := PasetoV4LocalDecrypt(tok, k, nil, []byte("class=1")); return err },
		"other key":      func() error { _, err := PasetoV4LocalDecrypt(tok, other, []byte("f"), []byte("class=1")); return err },
	}
	for name, fn := range cases {
		if err := fn(); !errors.Is(err, ErrPasetoInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPasetoV4LocalRejectsNonCanonicalAndMalformed(t *testing.T) {
	k := pasetoKey(t, 0x70)
	tok, err := PasetoV4LocalEncrypt(k, []byte("m"), []byte("f"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(tok, ".Zg") {
		t.Fatalf("footer encoding %q", tok[len(tok)-3:])
	}
	body := tok[:len(tok)-3]
	last := strings.IndexByte(pasetoAlphabet, body[len(body)-1])
	bad := []string{
		"",
		"v4.local.",
		"v4.local.A",
		tok + "=",
		tok[:len(tok)-1] + "h",
		body[:len(body)-1] + string(pasetoAlphabet[last|1]) + ".Zg",
		body + ".",
		body + "..Zg",
		body + ".Zg.Zg",
		strings.Replace(tok, "v4.local.", "v4.public.", 1),
		strings.Replace(tok, "v4.local.", "v3.local.", 1),
		tok[:20] + "+" + tok[21:],
		tok[:20] + "/" + tok[21:],
		tok[:20] + " " + tok[20:],
		tok + "\n",
	}
	for n, b := range bad {
		if _, err := PasetoV4LocalDecrypt(b, k, []byte("f"), nil); !errors.Is(err, ErrPasetoInvalid) {
			t.Errorf("case %d %.30q: %v", n, b, err)
		}
	}
	if _, err := PasetoV4LocalDecrypt(tok, k, []byte("f"), nil); err != nil {
		t.Fatalf("unmodified token: %v", err)
	}
}

const pasetoAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func TestPasetoV4LocalLengthsAndKeys(t *testing.T) {
	k := pasetoKey(t, 0x70)
	huge := make([]byte, PasetoV4MaxInputBytes+1)
	if _, err := PasetoV4LocalEncrypt(k, huge, nil, nil); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("oversize message: %v", err)
	}
	if _, err := PasetoV4LocalEncrypt(k, nil, huge, nil); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("oversize footer: %v", err)
	}
	if _, err := PasetoV4LocalEncrypt(k, nil, nil, huge); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("oversize implicit: %v", err)
	}
	tok, err := PasetoV4LocalEncrypt(k, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PasetoV4LocalDecrypt(tok, k, nil, huge); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("oversize implicit on decrypt: %v", err)
	}
	if m, err := PasetoV4LocalDecrypt(tok, k, nil, nil); err != nil || len(m) != 0 {
		t.Fatalf("empty message: %q, %v", m, err)
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := PasetoV4LocalEncrypt(counting(n, 0), []byte("m"), nil, nil); !errors.Is(err, ErrPasetoKey) {
			t.Fatalf("encrypt key of %d bytes: %v", n, err)
		}
		if _, err := PasetoV4LocalDecrypt(tok, counting(n, 0), nil, nil); !errors.Is(err, ErrPasetoKey) {
			t.Fatalf("decrypt key of %d bytes: %v", n, err)
		}
	}
}

func TestPasetoV4LocalConcurrent(t *testing.T) {
	k := pasetoKey(t, 0x70)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			msg := bytes.Repeat([]byte{byte(g)}, 200)
			for n := 0; n < 500; n++ {
				tok, err := PasetoV4LocalEncrypt(k, msg, []byte("footer"), nil)
				if err != nil {
					errs <- err
					return
				}
				got, err := PasetoV4LocalDecrypt(tok, k, []byte("footer"), nil)
				if err != nil || !bytes.Equal(got, msg) {
					errs <- errors.New("round trip mismatch")
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

const pasetoVectorFile = "../../../../tests/vectors/paseto/v4.json"

const pasetoVectorSHA256 = "0b72948b65d1f73f574c9ad2aa3481ec27bf8c632f5f6e1596cd41f5b9703387"

var pasetoVectorNames = []string{
	"4-E-1", "4-E-2", "4-E-3", "4-E-4", "4-E-5", "4-E-6", "4-E-7", "4-E-8", "4-E-9",
	"4-F-1", "4-F-2", "4-F-3", "4-F-4", "4-F-5",
}

type pasetoVector struct {
	Name       string  `json:"name"`
	ExpectFail bool    `json:"expect-fail"`
	Key        string  `json:"key"`
	PublicKey  string  `json:"public-key"`
	Nonce      string  `json:"nonce"`
	Token      string  `json:"token"`
	Payload    *string `json:"payload"`
	Footer     string  `json:"footer"`
	Implicit   string  `json:"implicit-assertion"`
}

func TestPasetoV4LocalOfficialVectors(t *testing.T) {
	data, err := os.ReadFile(pasetoVectorFile)
	if err != nil {
		t.Fatalf("the official vectors are vendored and must be present: %v", err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != pasetoVectorSHA256 {
		t.Fatalf("v4.json sha256 %x, want %s", sum, pasetoVectorSHA256)
	}
	var file struct {
		Tests []pasetoVector `json:"tests"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("v4.json: %v", err)
	}
	var ran []string
	for _, v := range file.Tests {
		if !strings.HasPrefix(v.Name, "4-E-") && !strings.HasPrefix(v.Name, "4-F-") {
			continue
		}
		ran = append(ran, v.Name)
		t.Run(v.Name, func(t *testing.T) { checkPasetoVector(t, v) })
	}
	if strings.Join(ran, ",") != strings.Join(pasetoVectorNames, ",") {
		t.Fatalf("ran %v, want exactly %v", ran, pasetoVectorNames)
	}
}

func checkPasetoVector(t *testing.T, v pasetoVector) {
	if strings.HasPrefix(v.Name, "4-E-") == v.ExpectFail {
		t.Fatalf("expect-fail %v for %s", v.ExpectFail, v.Name)
	}
	if v.Name == "4-F-1" {
		if v.Key != "" || v.PublicKey == "" {
			t.Fatal("4-F-1 must be the v4.public key misused as a v4.local key")
		}
		t.Log("4-F-1 checks key typing: this binding takes raw key bytes, so keeping a v4.public key out of v4.local is the caller's job (PASERK typing)")
		return
	}
	key, err := hex.DecodeString(v.Key)
	if err != nil || len(key) != PasetoV4LocalKeyBytes {
		t.Fatalf("key %q", v.Key)
	}
	got, derr := PasetoV4LocalDecrypt(v.Token, key, []byte(v.Footer), []byte(v.Implicit))
	if v.ExpectFail {
		if !errors.Is(derr, ErrPasetoInvalid) {
			t.Fatalf("got %q, %v, want ErrPasetoInvalid", got, derr)
		}
		return
	}
	if derr != nil || v.Payload == nil || string(got) != *v.Payload {
		t.Fatalf("decrypt: %q, %v", got, derr)
	}
	buf := make([]byte, PasetoV4LocalDecryptCap(len(v.Token)))
	n, err := PasetoV4LocalDecryptTo(buf, v.Token, key, []byte(v.Footer), []byte(v.Implicit))
	if err != nil || string(buf[:n]) != *v.Payload {
		t.Fatalf("decrypt into buffer: %q, %v", buf[:n], err)
	}
	checkPasetoVectorEncrypt(t, v, key)
}

func TestPasetoV4LocalLengthsMatchNative(t *testing.T) {
	sizes := []int{PasetoV4MaxInputBytes - 1, PasetoV4MaxInputBytes, PasetoV4MaxInputBytes + 1}
	for i := 0; i < 260; i++ {
		sizes = append(sizes, i)
	}
	for _, m := range sizes {
		for _, f := range sizes {
			if got, want := PasetoV4LocalEncryptLen(m, f), nativePasetoV4LocalEncryptLen(m, f); got != want {
				t.Fatalf("EncryptLen(%d, %d) = %d, native %d", m, f, got, want)
			}
		}
	}
	if PasetoV4LocalEncryptLen(-1, 0) != 0 || PasetoV4LocalEncryptLen(0, -1) != 0 || PasetoV4LocalDecryptCap(-1) != 0 {
		t.Fatal("negative lengths must give 0")
	}
	top := PasetoV4LocalEncryptLen(PasetoV4MaxInputBytes, PasetoV4MaxInputBytes)
	for _, n := range []int{top - 1, top, top + 1, top + 4} {
		if got, want := PasetoV4LocalDecryptCap(n), nativePasetoV4LocalDecryptCap(n); got != want {
			t.Fatalf("DecryptCap(%d) = %d, native %d", n, got, want)
		}
	}
	for n := 0; n < 3000; n++ {
		if got, want := PasetoV4LocalDecryptCap(n), nativePasetoV4LocalDecryptCap(n); got != want {
			t.Fatalf("DecryptCap(%d) = %d, native %d", n, got, want)
		}
	}
}

func TestPasetoV4LocalDecryptToContract(t *testing.T) {
	k := pasetoKey(t, 0x70)
	f, i := []byte(`{"kid":"a"}`), []byte("ctx")
	tok, err := PasetoV4LocalEncrypt(k, []byte("payload"), f, i)
	if err != nil {
		t.Fatal(err)
	}
	capN := PasetoV4LocalDecryptCap(len(tok))
	buf := bytes.Repeat([]byte{0xa5}, capN+1)
	if n, err := PasetoV4LocalDecryptTo(buf[:capN-1], tok, k, f, i); n != 0 || !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("short buffer: %d, %v", n, err)
	}
	n, err := PasetoV4LocalDecryptTo(buf, tok, k, f, i)
	if err != nil || string(buf[:n]) != "payload" || buf[capN] != 0xa5 {
		t.Fatalf("got %q, %v", buf[:n], err)
	}
	if !bytes.Equal(buf[n:capN], make([]byte, capN-n)) {
		t.Fatal("the capacity after the message must be zero")
	}
	for j := range buf {
		buf[j] = 0xa5
	}
	if n, err := PasetoV4LocalDecryptTo(buf, tok, k, f, []byte("other")); n != 0 || !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("wrong implicit: %d, %v", n, err)
	}
	if !bytes.Equal(buf[:capN], make([]byte, capN)) || buf[capN] != 0xa5 {
		t.Fatal("a failed decrypt must zero exactly its capacity")
	}
	if _, err := PasetoV4LocalDecryptTo(buf, tok, k[:31], f, i); !errors.Is(err, ErrPasetoKey) {
		t.Fatalf("short key: %v", err)
	}
	alias := []byte(tok)
	if _, err := PasetoV4LocalDecryptTo(alias, unsafe.String(&alias[0], len(alias)), k, f, i); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("overlapping buffer: %v", err)
	}
	var stack [512]byte
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := PasetoV4LocalDecryptTo(stack[:], tok, k, f, i); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("PasetoV4LocalDecryptTo allocated %v times", allocs)
	}
	allocs = testing.AllocsPerRun(100, func() {
		if _, err := PasetoV4LocalEncrypt(k, []byte("payload"), f, i); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 1 {
		t.Fatalf("PasetoV4LocalEncrypt allocated %v times, want 1 (the token)", allocs)
	}
}

func pasetoBench(b *testing.B) ([]byte, []byte, []byte, string) {
	k := pasetoKey(b, 0x70)
	msg := bytes.Repeat([]byte("a"), 200)
	footer := bytes.Repeat([]byte("f"), 60)
	tok, err := PasetoV4LocalEncrypt(k, msg, footer, nil)
	if err != nil {
		b.Fatal(err)
	}
	return k, msg, footer, tok
}

func BenchmarkPasetoV4LocalEncrypt(b *testing.B) {
	k, msg, footer, _ := pasetoBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := PasetoV4LocalEncrypt(k, msg, footer, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasetoV4LocalDecrypt(b *testing.B) {
	k, _, footer, tok := pasetoBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := PasetoV4LocalDecrypt(tok, k, footer, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasetoV4LocalDecryptTo(b *testing.B) {
	k, _, footer, tok := pasetoBench(b)
	var out [512]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := PasetoV4LocalDecryptTo(out[:], tok, k, footer, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasetoV4LocalEncryptParallel(b *testing.B) {
	k, msg, footer, _ := pasetoBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := PasetoV4LocalEncrypt(k, msg, footer, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkPasetoV4LocalDecryptParallel(b *testing.B) {
	k, _, footer, tok := pasetoBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := PasetoV4LocalDecrypt(tok, k, footer, nil); err != nil {
				b.Error(err)
				return
			}
		}
	})
}
