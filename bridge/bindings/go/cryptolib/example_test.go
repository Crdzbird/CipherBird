package cryptolib_test

// Runnable examples. These render on pkg.go.dev and are executed by `go test`,
// so they double as documentation and as a smoke test. Run them with the native
// library on the loader path:
//
//	DYLD_LIBRARY_PATH=../../../build/release go test ./cryptolib   # macOS
//	LD_LIBRARY_PATH=../../../build/release  go test ./cryptolib    # Linux

import (
	"encoding/hex"
	"fmt"

	"github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
)

// The library must be initialised once before use. Init is safe to call more
// than once, so each example calls it defensively.
func ExampleInit() {
	if err := cryptolib.Init(); err != nil {
		panic(err)
	}
	fmt.Println("ready")
	// Output: ready
}

// SHA-256 of a known input (a fixed digest, so the output is stable).
func ExampleSHA256() {
	_ = cryptolib.Init()
	sum, _ := cryptolib.SHA256([]byte("abc"))
	fmt.Println(hex.EncodeToString(sum))
	// Output: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}

// Keccak-256 is the original-padding variant used by Ethereum (not NIST SHA3).
func ExampleKeccak256() {
	_ = cryptolib.Init()
	d, _ := cryptolib.Keccak256([]byte("abc"))
	fmt.Println(hex.EncodeToString(d))
	// Output: 4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
}

// Authenticated symmetric encryption with XChaCha20-Poly1305. The nonce is
// generated and prepended internally; decryption authenticates before returning.
func ExampleXChaCha20Encrypt() {
	_ = cryptolib.Init()
	key, _ := cryptolib.SymKeygen()
	ct, _ := cryptolib.XChaCha20Encrypt([]byte("attack at dawn"), key, []byte("hdr"))
	pt, _ := cryptolib.XChaCha20Decrypt(ct, key, []byte("hdr"))
	fmt.Printf("%s\n", pt)
	// Output: attack at dawn
}

// Ed25519 detached signatures.
func ExampleEd25519Sign() {
	_ = cryptolib.Init()
	kp := cryptolib.Ed25519Keygen()
	msg := []byte("sign me")
	sig, _ := cryptolib.Ed25519Sign(msg, kp.Secret)
	fmt.Println(cryptolib.Ed25519Verify(msg, sig, kp.Public))
	// Output: true
}

// secp256k1 ECDSA with public-key recovery — the EVM "ecrecover" flow. Sign
// produces a 65-byte recoverable signature (r‖s‖v); Recover returns the signer's
// uncompressed public key.
func ExampleSecp256k1Sign() {
	_ = cryptolib.Init()
	kp := cryptolib.Secp256k1Keygen()
	digest, _ := cryptolib.Keccak256([]byte("transfer 1 ETH"))
	sig, _ := cryptolib.Secp256k1Sign(digest, kp.Secret)
	recovered, _ := cryptolib.Secp256k1Recover(digest, sig)
	fmt.Println(len(sig), string(equalLabel(recovered, kp.Public)))
	// Output: 65 recovered==signer
}

// The 4-layer vault: KDF → integrity → AEAD → signature, behind seal/open.
// Always Close the handle (defer) to release native memory deterministically.
func ExampleVault() {
	_ = cryptolib.Init()
	masterKey, _ := cryptolib.RandomBytes(32)

	v, err := cryptolib.NewVault(masterKey, cryptolib.KdfInteractive)
	if err != nil {
		panic(err)
	}
	defer v.Close()

	pkt, _ := v.Seal([]byte("top secret"), "context")
	pt, _ := v.Open(pkt, "context")
	fmt.Printf("%s\n", pt)
	// Output: top secret
}

// BLS12-381 signature aggregation: many signatures over distinct messages
// collapse into one 96-byte aggregate that verifies against all signers at once.
func ExampleBlsAggregate() {
	_ = cryptolib.Init()
	a, b := cryptolib.BlsKeygen(), cryptolib.BlsKeygen()
	m1, m2 := []byte("msg-1"), []byte("msg-2")
	s1, _ := cryptolib.BlsSign(m1, a.Secret)
	s2, _ := cryptolib.BlsSign(m2, b.Secret)

	agg, _ := cryptolib.BlsAggregate([][]byte{s1, s2})
	ok := cryptolib.BlsAggregateVerify(
		[][]byte{m1, m2}, [][]byte{a.Public, b.Public}, agg)
	fmt.Println(len(agg), ok)
	// Output: 96 true
}

// Streaming AEAD in one shot: encrypt a sequence of chunks and decrypt them
// back. For incremental streaming, use NewStreamEncryptor / NewStreamDecryptor.
func ExampleStreamEncrypt() {
	_ = cryptolib.Init()
	key, _ := cryptolib.RandomBytes(32)
	plain := [][]byte{[]byte("part-1"), []byte("part-2"), []byte("part-3")}

	header, ct, _ := cryptolib.StreamEncrypt(key, plain)
	pt, _ := cryptolib.StreamDecrypt(key, header, ct)

	fmt.Println(len(header), string(pt[0]), string(pt[1]), string(pt[2]))
	// Output: 24 part-1 part-2 part-3
}

func equalLabel(a, b []byte) []byte {
	if len(a) == len(b) && string(a) == string(b) {
		return []byte("recovered==signer")
	}
	return []byte("mismatch")
}
