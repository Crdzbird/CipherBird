package cryptolib

import (
	"bytes"
	"sync"
	"testing"
)

func handshake(t *testing.T) (*Noise, *Noise) {
	t.Helper()
	iks, rks := X25519Keygen(), X25519Keygen()
	ini, err := NewNoise(true, iks.Public, iks.Secret, []byte("prologue"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewNoise(false, rks.Public, rks.Secret, []byte("prologue"))
	if err != nil {
		t.Fatal(err)
	}
	m0, err := ini.WriteMessage([]byte("hello"))
	if err != nil {
		t.Fatalf("m0: %v", err)
	}
	if p, err := res.ReadMessage(m0); err != nil || string(p) != "hello" {
		t.Fatalf("read m0: %v %q", err, p)
	}
	m1, _ := res.WriteMessage(nil)
	if _, err := ini.ReadMessage(m1); err != nil {
		t.Fatalf("read m1: %v", err)
	}
	m2, _ := ini.WriteMessage(nil)
	if _, err := res.ReadMessage(m2); err != nil {
		t.Fatalf("read m2: %v", err)
	}
	if !ini.HandshakeFinished() || !res.HandshakeFinished() {
		t.Fatal("handshake should be finished")
	}
	// Mutual static authentication: each side learned the other's key.
	if rs, _ := ini.RemoteStatic(); !bytes.Equal(rs, rks.Public) {
		t.Fatal("initiator learned wrong remote static")
	}
	if rs, _ := res.RemoteStatic(); !bytes.Equal(rs, iks.Public) {
		t.Fatal("responder learned wrong remote static")
	}
	hi, _ := ini.HandshakeHash()
	hr, _ := res.HandshakeHash()
	if len(hi) != 32 || !bytes.Equal(hi, hr) {
		t.Fatal("handshake hashes must be 32 bytes and agree")
	}
	if err := ini.Split(); err != nil {
		t.Fatal(err)
	}
	if err := res.Split(); err != nil {
		t.Fatal(err)
	}
	if err := ini.Split(); err == nil {
		t.Fatal("second Split must fail")
	}
	return ini, res
}

func TestNoiseXXHandshakeAndTransport(t *testing.T) {
	ini, res := handshake(t)
	defer ini.Close()
	defer res.Close()

	ct, err := ini.Encrypt([]byte("first record"), []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := res.Decrypt(ct, []byte("ad"))
	if err != nil || string(pt) != "first record" {
		t.Fatalf("decrypt: %v %q", err, pt)
	}
	// Other direction works too.
	ct2, _ := res.Encrypt([]byte("reply"), nil)
	if pt2, err := ini.Decrypt(ct2, nil); err != nil || string(pt2) != "reply" {
		t.Fatalf("reverse decrypt: %v", err)
	}
	// Tamper fails closed; wrong AD fails closed.
	bad := append([]byte(nil), ct...)
	bad[0] ^= 1
	if _, err := res.Decrypt(bad, []byte("ad")); err == nil {
		t.Fatal("tampered record must be rejected")
	}
	// Encrypting before split fails.
	fresh, _ := NewNoise(true, X25519Keygen().Public, X25519Keygen().Secret, nil)
	defer fresh.Close()
	if _, err := fresh.Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("encrypt before split must fail")
	}
	res.Close()
	res.Close() // idempotent
}

func TestNoiseDecryptAtIsReentrantAndOrderIndependent(t *testing.T) {
	ini, res := handshake(t)
	defer ini.Close()
	defer res.Close()

	texts := []string{"r0", "record one", "r2", "r3", "r4"}
	records := make([][]byte, len(texts))
	for i, s := range texts {
		records[i], _ = ini.Encrypt([]byte(s), nil)
	}
	// Open concurrently, out of order, on ONE handle — the re-entrancy claim.
	var wg sync.WaitGroup
	got := make([][]byte, len(texts))
	errs := make([]error, len(texts))
	for i := len(records) - 1; i >= 0; i-- {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i], errs[i] = res.DecryptAt(uint64(i), records[i], nil)
		}(i)
	}
	wg.Wait()
	for i := range texts {
		if errs[i] != nil || string(got[i]) != texts[i] {
			t.Fatalf("record %d: %v %q", i, errs[i], got[i])
		}
	}
	// The session counter was untouched: sequential decrypt still opens r0.
	if pt, err := res.Decrypt(records[0], nil); err != nil || string(pt) != "r0" {
		t.Fatalf("sequential path disturbed: %v", err)
	}
	// Wrong counter is rejected — the tag binds it.
	if _, err := res.DecryptAt(1, records[0], nil); err == nil {
		t.Fatal("wrong counter must be rejected")
	}
	// Reserved maximum counter refused outright.
	if _, err := res.DecryptAt(^uint64(0), records[0], nil); err == nil {
		t.Fatal("reserved nonce must be rejected")
	}
}

func TestBlake3HasherMatchesOneShot(t *testing.T) {
	msg := []byte("incremental hashing across several chunks of input")
	want, _ := Blake3(msg, 32)

	h, err := NewBlake3Hasher(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	// Feed in uneven pieces; the digest must not depend on chunking.
	for _, piece := range [][]byte{msg[:7], msg[7:20], msg[20:]} {
		if err := h.Update(piece); err != nil {
			t.Fatal(err)
		}
	}
	got, err := h.Finalize(0)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("incremental != one-shot: %v", err)
	}
	if err := h.Update([]byte("late")); err == nil {
		t.Fatal("update after finalize must fail")
	}

	// Keyed mode: distinct from unkeyed, and rejects a bad key length.
	key := make([]byte, 32)
	kh, _ := NewBlake3Hasher(key)
	defer kh.Close()
	kh.Update(msg)
	keyed, _ := kh.Finalize(0)
	if bytes.Equal(keyed, want) {
		t.Fatal("keyed digest must differ from unkeyed")
	}
	if _, err := NewBlake3Hasher(make([]byte, 31)); err == nil {
		t.Fatal("31-byte key must be refused")
	}
	// Extendable output.
	xh, _ := NewBlake3Hasher(nil)
	defer xh.Close()
	xh.Update(msg)
	if xof, _ := xh.Finalize(64); len(xof) != 64 || !bytes.Equal(xof[:32], want) {
		t.Fatal("XOF prefix must equal the 32-byte digest")
	}
	h.Close()
	h.Close() // idempotent
}
