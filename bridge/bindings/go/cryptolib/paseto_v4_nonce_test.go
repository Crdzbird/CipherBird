//go:build cryptolib_paseto_test_nonce

package cryptolib

import (
	"encoding/hex"
	"testing"
)

func checkPasetoVectorEncrypt(t *testing.T, v pasetoVector, key []byte) {
	nonce, err := hex.DecodeString(v.Nonce)
	if err != nil {
		t.Fatalf("nonce %q", v.Nonce)
	}
	tok, err := PasetoV4LocalEncryptWithNonceForTesting(key, []byte(*v.Payload), []byte(v.Footer), []byte(v.Implicit), nonce)
	if err != nil || tok != v.Token {
		t.Fatalf("encrypt:\n got %s\nwant %s\n%v", tok, v.Token, err)
	}
}

func TestPasetoV4LocalTestNonceIsDeterministic(t *testing.T) {
	k := pasetoKey(t, 0x70)
	n := counting(32, 0x40)
	a, err := PasetoV4LocalEncryptWithNonceForTesting(k, []byte("m"), []byte("f"), []byte("i"), n)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PasetoV4LocalEncryptWithNonceForTesting(k, []byte("m"), []byte("f"), []byte("i"), n)
	if err != nil || a != b {
		t.Fatalf("same nonce gave %q and %q, %v", a, b, err)
	}
	if _, err := PasetoV4LocalEncryptWithNonceForTesting(k, []byte("m"), nil, nil, n[:31]); err == nil {
		t.Fatal("a 31-byte nonce must be rejected")
	}
	if got, err := PasetoV4LocalDecrypt(a, k, []byte("f"), []byte("i")); err != nil || string(got) != "m" {
		t.Fatalf("decrypt: %q, %v", got, err)
	}
}
