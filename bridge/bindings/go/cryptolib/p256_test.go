package cryptolib

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
)

const p256VectorFile = "../../../../tests/vectors/p256/ecdsa_p256_sha256.json"

type p256Vectors struct {
	RFC6979 struct {
		D     string `json:"d"`
		Qx    string `json:"qx"`
		Qy    string `json:"qy"`
		Cases []struct {
			Message string `json:"message"`
			R       string `json:"r"`
			S       string `json:"s"`
		} `json:"cases"`
	} `json:"rfc6979"`
	KeyPair []struct{ D, Qx, Qy string } `json:"keypair"`
	PKV     []struct {
		Qx, Qy string
		Valid  bool
		Note   string
	} `json:"pkv"`
	SigVer []struct {
		Message, Qx, Qy, R, S string
		Valid                 bool
		Note                  string
	} `json:"sigver"`
	SigGen []struct{ Message, D, Qx, Qy, R, S string } `json:"siggen"`
}

func p256Hex(t *testing.T, parts ...string) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		if len(p)%2 == 1 {
			p = "0" + p
		}
		b, err := hex.DecodeString(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return out
}

func p256Point(t *testing.T, qx, qy string) []byte {
	return append([]byte{0x04}, p256Hex(t, qx, qy)...)
}

func p256Load(t *testing.T) p256Vectors {
	t.Helper()
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if !P256Available() {
		t.Skip("P-256 is not in this build")
	}
	data, err := os.ReadFile(p256VectorFile)
	if err != nil {
		t.Skipf("vectors not present: %v", err)
	}
	var v p256Vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestP256Vectors(t *testing.T) {
	v := p256Load(t)
	if len(v.KeyPair) != 10 || len(v.PKV) != 12 || len(v.SigVer) != 15 || len(v.SigGen) != 15 || len(v.RFC6979.Cases) != 2 {
		t.Fatalf("unexpected vector counts")
	}
	for _, c := range v.KeyPair {
		pk, err := P256PublicKey(p256Hex(t, c.D))
		if err != nil || !bytes.Equal(pk, p256Point(t, c.Qx, c.Qy)) {
			t.Fatalf("keypair %s: %v", c.D[:8], err)
		}
	}
	for _, c := range v.SigVer {
		got := P256Verify(p256Point(t, c.Qx, c.Qy), p256Hex(t, c.Message), p256Hex(t, c.R, c.S))
		if got != c.Valid {
			t.Fatalf("sigver %q: got %v", c.Note, got)
		}
	}
	for _, c := range v.SigGen {
		d, q, m := p256Hex(t, c.D), p256Point(t, c.Qx, c.Qy), p256Hex(t, c.Message)
		if !P256Verify(q, m, p256Hex(t, c.R, c.S)) {
			t.Fatalf("siggen %s: recorded signature refused", c.D[:8])
		}
		sig, err := P256Sign(d, m)
		if err != nil || !P256Verify(q, m, sig) {
			t.Fatalf("siggen %s: own signature refused: %v", c.D[:8], err)
		}
	}
	d, q := p256Hex(t, v.RFC6979.D), p256Point(t, v.RFC6979.Qx, v.RFC6979.Qy)
	for _, c := range v.RFC6979.Cases {
		want := p256Hex(t, c.R, c.S)
		if !P256Verify(q, []byte(c.Message), want) {
			t.Fatalf("rfc6979 %q: answer refused", c.Message)
		}
		sig, err := P256Sign(d, []byte(c.Message))
		if err != nil {
			t.Fatal(err)
		}
		if P256DeterministicNonces() && !bytes.Equal(sig, want) {
			t.Fatalf("rfc6979 %q: got %x", c.Message, sig)
		}
	}
	valid := 0
	for _, c := range v.PKV {
		q := p256Point(t, c.Qx, c.Qy)
		x, y := new(big.Int).SetBytes(p256Hex(t, c.Qx)), new(big.Int).SetBytes(p256Hex(t, c.Qy))
		if elliptic.P256().IsOnCurve(x, y) != c.Valid {
			t.Fatalf("pkv %q: Go disagrees with the vector", c.Note)
		}
		if !c.Valid && P256Verify(q, []byte("m"), p256Hex(t, v.RFC6979.Cases[0].R, v.RFC6979.Cases[0].S)) {
			t.Fatalf("pkv %q: an invalid point verified", c.Note)
		}
		if c.Valid {
			valid++
		}
	}
	if valid != 4 {
		t.Fatalf("pkv: %d valid", valid)
	}
}

func p256Raw(r, s *big.Int) []byte {
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out
}

func TestP256AgainstGoCryptoECDSA(t *testing.T) {
	p256Load(t)
	half := new(big.Int).Rsh(elliptic.P256().Params().N, 1)
	highS := 0
	for i := 0; i < 64; i++ {
		kp, err := P256GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(kp.Secret) != P256SecretKeyBytes || len(kp.Public) != P256PublicKeyBytes || kp.Public[0] != 0x04 {
			t.Fatalf("key shape: %d %d", len(kp.Secret), len(kp.Public))
		}
		derived, err := P256PublicKey(kp.Secret)
		if err != nil || !bytes.Equal(derived, kp.Public) {
			t.Fatalf("public key: %v", err)
		}
		msg := make([]byte, i*7)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(msg)
		goPub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(kp.Public[1:33]), Y: new(big.Int).SetBytes(kp.Public[33:])}
		sig, err := P256Sign(kp.Secret, msg)
		if err != nil || len(sig) != P256SignatureBytes {
			t.Fatalf("sign: %v", err)
		}
		if !ecdsa.Verify(goPub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			t.Fatalf("round %d: Go refused a cryptolib signature", i)
		}
		if !P256Verify(kp.Public, msg, sig) {
			t.Fatalf("round %d: cryptolib refused its own signature", i)
		}

		goKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r, s, err := ecdsa.Sign(rand.Reader, goKey, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		if s.Cmp(half) > 0 {
			highS++
		}
		goPubBytes := elliptic.Marshal(elliptic.P256(), goKey.X, goKey.Y)
		if !P256Verify(goPubBytes, msg, p256Raw(r, s)) {
			t.Fatalf("round %d: cryptolib refused a Go signature", i)
		}
		flipped := new(big.Int).Sub(elliptic.P256().Params().N, s)
		if !P256Verify(goPubBytes, msg, p256Raw(r, flipped)) {
			t.Fatalf("round %d: the other half of the s range was refused", i)
		}
		if P256Verify(goPubBytes, append(msg, 0), p256Raw(r, s)) || P256Verify(kp.Public, msg, p256Raw(r, s)) {
			t.Fatalf("round %d: a wrong message or key verified", i)
		}
		d := make([]byte, 32)
		goKey.D.FillBytes(d)
		pk, err := P256PublicKey(d)
		if err != nil || !bytes.Equal(pk, goPubBytes) {
			t.Fatalf("round %d: public key of a Go scalar: %v", i, err)
		}
	}
	t.Logf("64 rounds each way; %d of the Go signatures had s in the upper half", highS)
}

func TestP256PKCS8AgainstGoX509(t *testing.T) {
	p256Load(t)
	for i := 0; i < 16; i++ {
		goKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(goKey)
		if err != nil {
			t.Fatal(err)
		}
		d := make([]byte, 32)
		goKey.D.FillBytes(d)
		pub := elliptic.Marshal(elliptic.P256(), goKey.X, goKey.Y)
		kp, err := P256PrivateKeyFromPKCS8(der)
		if err != nil || !bytes.Equal(kp.Secret, d) || !bytes.Equal(kp.Public, pub) {
			t.Fatalf("der import: %v", err)
		}
		block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		kp2, err := P256PrivateKeyFromPEM(block)
		if err != nil || !bytes.Equal(kp2.Secret, d) || !bytes.Equal(kp2.Public, pub) {
			t.Fatalf("pem import: %v", err)
		}
		if _, err := P256PrivateKeyFromPKCS8(append(append([]byte(nil), der...), 0)); err == nil {
			t.Fatal("a trailing byte was accepted")
		}
		if _, err := P256PrivateKeyFromPKCS8(der[:len(der)-1]); err == nil {
			t.Fatal("a truncated key was accepted")
		}
		sec1, err := x509.MarshalECPrivateKey(goKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := P256PrivateKeyFromPKCS8(sec1); err == nil {
			t.Fatal("a SEC 1 key was accepted as PKCS#8")
		}
		if _, err := P256PrivateKeyFromPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})); err == nil || !strings.Contains(err.Error(), "SEC 1") {
			t.Fatalf("SEC 1 PEM: %v", err)
		}
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der384, _ := x509.MarshalPKCS8PrivateKey(p384)
	if _, err := P256PrivateKeyFromPKCS8(der384); err == nil || !strings.Contains(err.Error(), "P-256") {
		t.Fatalf("P-384: %v", err)
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	derEd, _ := x509.MarshalPKCS8PrivateKey(edKey)
	if _, err := P256PrivateKeyFromPKCS8(derEd); err == nil || !strings.Contains(err.Error(), "id-ecPublicKey") {
		t.Fatalf("Ed25519: %v", err)
	}
	if _, err := P256PrivateKeyFromPKCS8(nil); err == nil {
		t.Fatal("empty input was accepted")
	}
	if _, err := P256PrivateKeyFromPEM([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n")); err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("encrypted PEM: %v", err)
	}
}

func TestP256RefusesBadInput(t *testing.T) {
	v := p256Load(t)
	q := p256Point(t, v.RFC6979.Qx, v.RFC6979.Qy)
	c := v.RFC6979.Cases[0]
	sig := p256Hex(t, c.R, c.S)
	msg := []byte(c.Message)
	if !P256Verify(q, msg, sig) {
		t.Fatal("baseline")
	}
	n := p256Hex(t, "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
	zero := make([]byte, 32)
	bad := [][]byte{
		append(append([]byte(nil), zero...), sig[32:]...),
		append(append([]byte(nil), sig[:32]...), zero...),
		append(append([]byte(nil), n...), sig[32:]...),
		append(append([]byte(nil), sig[:32]...), n...),
		sig[:63], append(append([]byte(nil), sig...), 0), nil,
	}
	for i, s := range bad {
		if P256Verify(q, msg, s) {
			t.Fatalf("bad signature %d verified", i)
		}
	}
	compressed := append([]byte{0x02 | (q[64] & 1)}, q[1:33]...)
	off := append([]byte(nil), q...)
	off[64] ^= 1
	for i, k := range [][]byte{compressed, off, q[:64], q[1:], nil} {
		if P256Verify(k, msg, sig) {
			t.Fatalf("bad key %d verified", i)
		}
	}
	for i, sk := range [][]byte{zero, n, make([]byte, 31), make([]byte, 33), nil} {
		if _, err := P256Sign(sk, msg); err == nil {
			t.Fatalf("bad secret key %d signed", i)
		}
		if _, err := P256PublicKey(sk); err == nil {
			t.Fatalf("bad secret key %d has a public key", i)
		}
	}
	if s, err := P256Sign(p256Hex(t, v.RFC6979.D), nil); err != nil || !P256Verify(q, nil, s) {
		t.Fatalf("empty message: %v", err)
	}
}
