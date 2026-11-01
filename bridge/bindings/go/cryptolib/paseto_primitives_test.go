package cryptolib

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func counting(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func TestBlake2bKeyedKnownAnswers(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	pasetoKey := counting(32, 0x70)
	encMsg := append([]byte("paseto-encryption-key"), make([]byte, 32)...)
	authMsg := append([]byte("paseto-auth-key-for-aead"), make([]byte, 32)...)
	cases := []struct {
		name   string
		msg    []byte
		key    []byte
		outLen int
		want   string
	}{
		{"libsodium-exp-32", counting(31, 0), counting(32, 0), 32,
			"a9f51bb7f6a3e9cdb96ce652c07d177962a348a9cced1b92f948187e59b44463"},
		{"libsodium-exp-56", counting(55, 0), counting(56, 0), 56,
			"703d8e552236b2090143444545f0a61a809d8ef9843bcf6883f61671fb31c8d6" +
				"ac9fd373e7f9f79a0c72fa6a37dc655ba1fb01a5f41e36d1"},
		{"libsodium-exp-64", counting(63, 0), counting(64, 0), 64,
			"bd965bf31e87d70327536f2a341cebc4768eca275fa05ef98f7f1b71a0351298" +
				"de006fba73fe6733ed01d75801b4a928e54231b38e38c562b2e33ea1284992fa"},
		{"blake2-reference-empty", nil, counting(64, 0), 64,
			"10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786" +
				"b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"},
		{"v4-local-shaped-56", encMsg, pasetoKey, 56,
			"c32b8e1c522550c8854d5177eb2ca96acc2072e3ca58407e0ee2f6470e92e49f" +
				"129a23d170eddce49867d4888d276390abf7e48e550feb7c"},
		{"v4-local-shaped-32", authMsg, pasetoKey, 32,
			"3d6d4c0504cbefdc54a562967ca276d0a99e0120cf154cc8624feb26da3a73e9"},
		{"unkeyed-32-abc", []byte("abc"), nil, 32,
			"bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
		{"unkeyed-1-abc", []byte("abc"), nil, 1, "6b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Blake2bKeyed(tc.msg, tc.key, tc.outLen)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != tc.want {
				t.Fatalf("got %x", got)
			}
		})
	}
}

func TestBlake2bKeyedIsNotATruncation(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	full, err := Blake2b([]byte("abc"), nil)
	if err != nil {
		t.Fatal(err)
	}
	native, err := Blake2bKeyed([]byte("abc"), nil, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(full[:32], native) {
		t.Fatal("32-byte BLAKE2b must differ from a truncated 64-byte digest")
	}
	same, err := Blake2bKeyed([]byte("abc"), nil, 64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full, same) {
		t.Fatal("64-byte unkeyed output must equal Blake2b")
	}
}

func TestBlake2bKeyedRejectsBadLengths(t *testing.T) {
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	key := counting(65, 0)
	cases := []struct {
		name   string
		keyLen int
		outLen int
	}{
		{"out-negative", 32, -1},
		{"out-zero", 32, 0},
		{"out-65", 32, 65},
		{"key-1", 1, 32},
		{"key-15", 15, 32},
		{"key-65", 65, 32},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := Blake2bKeyed([]byte("m"), key[:tc.keyLen], tc.outLen)
			if err == nil || out != nil {
				t.Fatalf("expected an error and no output, got %x, %v", out, err)
			}
		})
	}
	for _, n := range []int{16, 64} {
		if _, err := Blake2bKeyed([]byte("m"), key[:n], 32); err != nil {
			t.Fatalf("key of %d bytes must be accepted: %v", n, err)
		}
	}
}
