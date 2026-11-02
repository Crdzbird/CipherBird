//go:build cryptolib_bank

package cryptolib

import (
	"errors"
	"testing"
)

// Against a bank-profile library the cb1 symbols link but report that the
// format is absent, and the PASETO v4.local functions keep working.
func TestCb1UnavailableInBankProfile(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	k := counting(32, 0x70)
	if _, err := Cb1LocalEncrypt(k, []byte("m"), nil, nil); !errors.Is(err, ErrPasetoUnavailable) {
		t.Fatalf("local encrypt: %v", err)
	}
	if _, err := Cb1LocalDecrypt("cb1.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", k, nil, nil); !errors.Is(err, ErrPasetoUnavailable) {
		t.Fatalf("local decrypt: %v", err)
	}
	kp := HybridSigKeygen()
	if _, err := Cb1PublicSign(kp.Secret, []byte("m"), nil, nil); !errors.Is(err, ErrPasetoUnavailable) {
		t.Fatalf("public sign: %v", err)
	}
	if nativeCb1LocalEncryptLen(1, 0) != 0 || nativeCb1PublicSignLen(1, 0) != 0 {
		t.Fatal("the bank stubs must report no length")
	}
	tok, err := PasetoV4LocalEncrypt(k, []byte("still here"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := PasetoV4LocalDecrypt(tok, k, nil, nil); err != nil || string(got) != "still here" {
		t.Fatalf("v4.local in the bank profile: %v", err)
	}
}
