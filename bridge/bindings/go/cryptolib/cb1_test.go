//go:build !cryptolib_bank

package cryptolib

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

const cb1VectorFile = "../../../../tests/vectors/cb1/vectors.json"

func cb1Signer(t testing.TB) KeyPair {
	t.Helper()
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	return HybridSigKeygen()
}

func TestCb1LocalRoundTrip(t *testing.T) {
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
		tok, err := Cb1LocalEncrypt(k, c.payload, c.f, c.i)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		dots := 2
		if len(c.f) > 0 {
			dots = 3
		}
		if !strings.HasPrefix(tok, "cb1.local.") || strings.Count(tok, ".") != dots || len(tok) != Cb1LocalEncryptLen(len(c.payload), len(c.f)) {
			t.Fatalf("%s: shape %.40q len %d", c.name, tok, len(tok))
		}
		got, err := Cb1LocalDecrypt(tok, k, c.f, c.i)
		if err != nil || !bytes.Equal(got, c.payload) || cap(got) != len(got) {
			t.Fatalf("%s: got %d bytes, %v", c.name, len(got), err)
		}
		if nativeCb1LocalEncryptLen(len(c.payload), len(c.f)) != len(tok) || nativeCb1LocalDecryptCap(len(tok)) != Cb1LocalDecryptCap(len(tok)) {
			t.Fatalf("%s: length helpers disagree with the native ones", c.name)
		}
	}
	a, _ := Cb1LocalEncrypt(k, []byte("m"), nil, nil)
	b, _ := Cb1LocalEncrypt(k, []byte("m"), nil, nil)
	if a == b {
		t.Fatal("nonce is not fresh")
	}
}

func TestCb1LocalTamperAndMismatch(t *testing.T) {
	k, other := pasetoKey(t, 0x70), counting(32, 0x90)
	f, i := []byte(`{"kid":"k"}`), []byte("bind")
	tok, err := Cb1LocalEncrypt(k, []byte(`{"data":"x"}`), f, i)
	if err != nil {
		t.Fatal(err)
	}
	for pos := 0; pos < len(tok); pos++ {
		for _, sub := range []byte{'A', 'z', '-', '.'} {
			if tok[pos] == sub {
				continue
			}
			x := []byte(tok)
			x[pos] = sub
			if _, err := Cb1LocalDecrypt(string(x), k, f, i); !errors.Is(err, ErrPasetoInvalid) {
				t.Fatalf("position %d accepted %q: %v", pos, sub, err)
			}
		}
	}
	for _, c := range []struct {
		name  string
		key   []byte
		f, i  []byte
		token string
	}{
		{"key", other, f, i, tok},
		{"footer", k, []byte("g"), i, tok},
		{"no footer", k, nil, i, tok},
		{"implicit", k, f, []byte("j"), tok},
		{"padding", k, f, i, tok + "="},
		{"truncated", k, f, i, tok[:len(tok)-1]},
		{"empty", k, f, i, ""},
		{"header only", k, f, i, "cb1.local."},
	} {
		if _, err := Cb1LocalDecrypt(c.token, c.key, c.f, c.i); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	v4, err := PasetoV4LocalEncrypt(k, []byte("m"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Cb1LocalDecrypt(v4, k, nil, nil); !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("a PASETO token was accepted as cb1: %v", err)
	}
	cb, _ := Cb1LocalEncrypt(k, []byte("m"), nil, nil)
	if _, err := PasetoV4LocalDecrypt(cb, k, nil, nil); !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("a cb1 token was accepted as PASETO: %v", err)
	}
	if _, err := Cb1LocalEncrypt(k[:31], nil, nil, nil); !errors.Is(err, ErrPasetoKey) {
		t.Fatalf("short key: %v", err)
	}
	if _, err := Cb1LocalDecrypt(tok, k[:31], f, i); !errors.Is(err, ErrPasetoKey) {
		t.Fatalf("short key on decrypt: %v", err)
	}
}

func TestCb1LocalDecryptToAllocatesNothing(t *testing.T) {
	k := pasetoKey(t, 0x70)
	tok, _ := Cb1LocalEncrypt(k, []byte("stream resume token"), []byte("f"), nil)
	var buf [256]byte
	allocs := testing.AllocsPerRun(50, func() {
		n, err := Cb1LocalDecryptTo(buf[:], tok, k, []byte("f"), nil)
		if err != nil || n != 19 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	})
	if allocs != 0 {
		t.Fatalf("decrypt allocated %v times", allocs)
	}
	if _, err := Cb1LocalDecryptTo(buf[:4], tok, k, []byte("f"), nil); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("small buffer: %v", err)
	}
}

func TestCb1PublicRoundTripAndTamper(t *testing.T) {
	kp := cb1Signer(t)
	other := HybridSigKeygen()
	if len(kp.Public) != Cb1PublicKeyBytes || len(kp.Secret) != Cb1SecretKeyBytes {
		t.Fatalf("hybrid key sizes %d/%d", len(kp.Public), len(kp.Secret))
	}
	cases := []struct {
		name          string
		payload, f, i []byte
	}{
		{"empty", nil, nil, nil},
		{"payload", []byte(`{"data":"x"}`), nil, nil},
		{"footer", []byte(`{"data":"x"}`), []byte(`{"kid":"a"}`), nil},
		{"all", bytes.Repeat([]byte{0xff}, 1000), []byte("f"), []byte("i")},
	}
	for _, c := range cases {
		tok, err := Cb1PublicSign(kp.Secret, c.payload, c.f, c.i)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !strings.HasPrefix(tok, "cb1.public.") || len(tok) != Cb1PublicSignLen(len(c.payload), len(c.f)) {
			t.Fatalf("%s: shape %.40q", c.name, tok)
		}
		got, err := Cb1PublicVerify(tok, kp.Public, c.f, c.i)
		if err != nil || !bytes.Equal(got, c.payload) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if nativeCb1PublicSignLen(len(c.payload), len(c.f)) != len(tok) || nativeCb1PublicVerifyCap(len(tok)) != Cb1PublicVerifyCap(len(tok)) {
			t.Fatalf("%s: length helpers disagree with the native ones", c.name)
		}
		if _, err := Cb1PublicVerify(tok, other.Public, c.f, c.i); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("%s: wrong key accepted: %v", c.name, err)
		}
	}
	tok, _ := Cb1PublicSign(kp.Secret, []byte(`{"data":"x"}`), []byte("f"), []byte("i"))
	for pos := 0; pos < len(tok); pos += 11 {
		x := []byte(tok)
		if x[pos] == 'A' {
			x[pos] = 'B'
		} else {
			x[pos] = 'A'
		}
		if _, err := Cb1PublicVerify(string(x), kp.Public, []byte("f"), []byte("i")); !errors.Is(err, ErrPasetoInvalid) {
			t.Fatalf("position %d accepted: %v", pos, err)
		}
	}
	if _, err := Cb1PublicVerify(tok, kp.Public, []byte("g"), []byte("i")); !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("footer: %v", err)
	}
	if _, err := Cb1PublicVerify(tok, kp.Public, []byte("f"), nil); !errors.Is(err, ErrPasetoInvalid) {
		t.Fatalf("implicit: %v", err)
	}
	if _, err := Cb1PublicSign(kp.Secret[:64], nil, nil, nil); !errors.Is(err, ErrPasetoKey) {
		t.Fatalf("short secret key: %v", err)
	}
	buf := make([]byte, Cb1PublicVerifyCap(len(tok)))
	if n, err := Cb1PublicVerifyTo(buf, tok, kp.Public, []byte("f"), []byte("i")); err != nil || n != 12 {
		t.Fatalf("verify to: n=%d %v", n, err)
	}
}

func TestCb1PinnedVectors(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(cb1VectorFile)
	if err != nil {
		t.Fatalf("the cb1 vectors are generated by the C++ suite and committed: %v", err)
	}
	var file struct {
		Local []struct {
			Name     string `json:"name"`
			Fail     bool   `json:"expect-fail"`
			Key      string `json:"key"`
			Token    string `json:"token"`
			Payload  string `json:"payload"`
			Footer   string `json:"footer"`
			Implicit string `json:"implicit-assertion"`
		} `json:"local"`
		Public []struct {
			Name      string `json:"name"`
			Fail      bool   `json:"expect-fail"`
			PublicKey string `json:"public-key"`
			SecretKey string `json:"secret-key"`
			Token     string `json:"token"`
			Payload   string `json:"payload"`
			Footer    string `json:"footer"`
			Implicit  string `json:"implicit-assertion"`
		} `json:"public"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Local) < 10 || len(file.Public) < 8 {
		t.Fatalf("expected the full vector set, got %d local and %d public", len(file.Local), len(file.Public))
	}
	for _, v := range file.Local {
		key, _ := hex.DecodeString(v.Key)
		got, err := Cb1LocalDecrypt(v.Token, key, []byte(v.Footer), []byte(v.Implicit))
		if v.Fail {
			if !errors.Is(err, ErrPasetoInvalid) {
				t.Fatalf("%s: want invalid, got %v", v.Name, err)
			}
			continue
		}
		if err != nil || string(got) != v.Payload {
			t.Fatalf("%s: %v %q", v.Name, err, got)
		}
	}
	for _, v := range file.Public {
		pk, _ := hex.DecodeString(v.PublicKey)
		sk, _ := hex.DecodeString(v.SecretKey)
		got, err := Cb1PublicVerify(v.Token, pk, []byte(v.Footer), []byte(v.Implicit))
		if v.Fail {
			if !errors.Is(err, ErrPasetoInvalid) {
				t.Fatalf("%s: want invalid, got %v", v.Name, err)
			}
			continue
		}
		if err != nil || string(got) != v.Payload {
			t.Fatalf("%s: %v %q", v.Name, err, got)
		}
		again, err := Cb1PublicSign(sk, []byte(v.Payload), []byte(v.Footer), []byte(v.Implicit))
		if err != nil {
			t.Fatalf("%s: re-sign: %v", v.Name, err)
		}
		if back, err := Cb1PublicVerify(again, pk, []byte(v.Footer), []byte(v.Implicit)); err != nil || string(back) != v.Payload {
			t.Fatalf("%s: re-signed token does not verify: %v", v.Name, err)
		}
	}
}

func TestBlake2bKeyedInto(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	key, msg := counting(32, 0x70), counting(77, 3)
	for _, n := range []int{1, 32, 56, 64} {
		want, err := Blake2bKeyed(msg, key, n)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, n)
		if err := Blake2bKeyedInto(out, msg, key); err != nil || !bytes.Equal(out, want) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
	var buf [32]byte
	allocs := testing.AllocsPerRun(50, func() {
		if err := Blake2bKeyedInto(buf[:], msg, key); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("keyed digest into a buffer allocated %v times", allocs)
	}
	if err := Blake2bKeyedInto(nil, msg, key); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("empty out: %v", err)
	}
	if err := Blake2bKeyedInto(make([]byte, 65), msg, key); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("65 bytes: %v", err)
	}
	if err := Blake2bKeyedInto(buf[:], msg, key[:15]); !errors.Is(err, ErrPasetoArgument) {
		t.Fatalf("short key: %v", err)
	}
}
