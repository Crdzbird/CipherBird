//go:build !cipherbird_bank

package cipherbird

import (
	"bytes"
	"testing"
)

func TestBlsKeygenFromIkmRefusesShortIkm(t *testing.T) {
	for _, n := range []int{0, 8, 31} {
		if _, err := BlsKeygenFromIkm(make([]byte, n)); err == nil {
			t.Fatalf("ikm of %d bytes: want an error", n)
		}
	}
	ikm := bytes.Repeat([]byte{7}, 32)
	a, err := BlsKeygenFromIkm(ikm)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BlsKeygenFromIkm(ikm)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Public) != 48 || !bytes.Equal(a.Public, b.Public) {
		t.Fatalf("want a deterministic 48-byte public key, got %d bytes", len(a.Public))
	}
}
