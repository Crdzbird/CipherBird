// CryptoLib Go — FULL showcase of every capability family via the cgo bindings.
//
//	DYLD_LIBRARY_PATH=../../../build/release go run ./showcase
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cryptolib"
)

var pass, fail int

func ck(label string, ok bool) {
	mark := "✓"
	if !ok {
		mark = "✗"
		fail++
	} else {
		pass++
	}
	fmt.Printf("  %s %s\n", mark, label)
}
func must(b []byte, err error) []byte {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	return b
}

func main() {
	if err := cryptolib.Init(); err != nil {
		panic(err)
	}
	fmt.Printf("CryptoLib %s — Go full showcase\n\n", cryptolib.Version())
	abc := []byte("abc")
	msg := []byte("secret payload")

	fmt.Println("HASHING")
	ck("SHA-256(abc) KAT", cryptolib.Hex(must(cryptolib.SHA256(abc))) ==
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	ck("SHA-512", len(must(cryptolib.SHA512(abc))) == 64)
	ck("BLAKE2b", len(must(cryptolib.Blake2b(abc, nil))) == 64)
	hkey := must(cryptolib.SymKeygen())
	mac := must(cryptolib.HmacSHA512(abc, hkey))
	ck("HMAC-SHA512 verify", cryptolib.HmacSHA512Verify(abc, mac, hkey))
	phc, _ := cryptolib.Argon2idHashStr("hunter2", 2, 67108864)
	ck("Argon2id PHC verify", cryptolib.Argon2idVerifyStr("hunter2", phc))

	fmt.Println("\nSYMMETRIC")
	sk := must(cryptolib.SymKeygen())
	xct := must(cryptolib.XChaCha20Encrypt(msg, sk, nil))
	ck("XChaCha20 round-trip", bytes.Equal(must(cryptolib.XChaCha20Decrypt(xct, sk, nil)), msg))
	if cryptolib.AES256GCMAvailable() {
		act := must(cryptolib.AES256GCMEncrypt(msg, sk, nil))
		ck("AES-256-GCM round-trip", bytes.Equal(must(cryptolib.AES256GCMDecrypt(act, sk, nil)), msg))
	} else {
		fmt.Println("    AES-256-GCM unavailable")
	}

	fmt.Println("\nASYMMETRIC")
	ed := cryptolib.Ed25519Keygen()
	sig := must(cryptolib.Ed25519Sign(abc, ed.Secret))
	ck("Ed25519 sign/verify", cryptolib.Ed25519Verify(abc, sig, ed.Public))
	xa, xb := cryptolib.X25519Keygen(), cryptolib.X25519Keygen()
	ck("X25519 ECDH", bytes.Equal(must(cryptolib.X25519SharedSecret(xa.Secret, xb.Public)),
		must(cryptolib.X25519SharedSecret(xb.Secret, xa.Public))))
	r, s := cryptolib.BoxKeygen(), cryptolib.BoxKeygen()
	bct := must(cryptolib.BoxEncrypt(msg, r.Public, s.Secret))
	ck("Box round-trip", bytes.Equal(must(cryptolib.BoxDecrypt(bct, s.Public, r.Secret)), msg))
	sct := must(cryptolib.SealedBoxEncrypt(msg, r.Public))
	ck("SealedBox round-trip", bytes.Equal(must(cryptolib.SealedBoxDecrypt(sct, r.Public, r.Secret)), msg))

	fmt.Println("\nVAULTS")
	vault, _ := cryptolib.NewVault(must(cryptolib.RandomBytes(32)), 0)
	pkt := mustPkt(vault.Seal(msg, "ctx"))
	ck("SecureVault round-trip", bytes.Equal(must(vault.Open(pkt, "ctx")), msg))
	vault.Close()
	alice, bob := cryptolib.AsymBundleGenerate(), cryptolib.AsymBundleGenerate()
	apkt := mustPkt(cryptolib.AsymVaultSeal(&alice, bob.BoxPublic, msg, "ctx"))
	ck("AsymmetricVault round-trip", bytes.Equal(must(cryptolib.AsymVaultOpen(apkt, &bob, alice.SignPublic, "ctx")), msg))

	fmt.Println("\nPOST-QUANTUM")
	kem := cryptolib.MlKemKeygen(1)
	enc, _ := cryptolib.MlKemEncapsulate(kem.Public, 1)
	ck("ML-KEM-768 encaps/decaps", bytes.Equal(enc.SharedSecret, must(cryptolib.MlKemDecapsulate(enc.Ciphertext, kem.Secret, 1))))
	hkem := cryptolib.HybridKemKeygen()
	henc, _ := cryptolib.HybridKemEncapsulate(hkem.Public)
	ck("Hybrid X25519+ML-KEM-768 encaps/decaps",
		bytes.Equal(henc.SharedSecret, must(cryptolib.HybridKemDecapsulate(henc.Ciphertext, hkem.Secret))) && len(henc.SharedSecret) == 32)
	dsa := cryptolib.MlDsaKeygen(1)
	dsig := must(cryptolib.MlDsaSign(abc, dsa.Secret, 1))
	ck("ML-DSA-65 sign/verify", cryptolib.MlDsaVerify(abc, dsig, dsa.Public, 1))
	slh := cryptolib.SlhDsaKeygen(1, 0)
	ssig := must(cryptolib.SlhDsaSign(abc, slh.Secret, 1, 0))
	ck("SLH-DSA-128f sign/verify", cryptolib.SlhDsaVerify(abc, ssig, slh.Public, 1, 0))

	fmt.Println("\nBLS12-381")
	bls := cryptolib.BlsKeygen()
	bsig := must(cryptolib.BlsSign(abc, bls.Secret))
	ck("BLS sign/verify", cryptolib.BlsVerify(abc, bsig, bls.Public))

	fmt.Println("\nKEYRING")
	factor := must(cryptolib.RandomBytes(32))
	kr := cryptolib.NewKeyring()
	kr.AddDeviceSlot(factor)
	kr.AddPassphraseSlot("cross-device pass", 0)
	blob := must(kr.Serialise())
	kr2, _ := cryptolib.DeserialiseKeyring(blob)
	ck(fmt.Sprintf("Keyring device==passphrase master (%d slots)", kr.SlotCount()),
		bytes.Equal(must(kr2.UnlockWithDevice(factor)), must(kr2.UnlockWithPassphrase("cross-device pass"))))
	kr.Close()
	kr2.Close()

	if fail == 0 {
		fmt.Printf("\nGo showcase OK (%d passed, 0 failed)\n", pass)
	} else {
		fmt.Printf("\nGo showcase FAILED (%d passed, %d failed)\n", pass, fail)
		os.Exit(1)
	}
}

func mustPkt(p *cryptolib.Packet, err error) *cryptolib.Packet {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	return p
}
