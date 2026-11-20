// CipherBird Go — FULL showcase of every capability family via the cgo bindings.
//
//	DYLD_LIBRARY_PATH=../../../build/release go run ./showcase
package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cipherbird"
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
	if err := cipherbird.Init(); err != nil {
		panic(err)
	}
	fmt.Printf("CipherBird %s — Go full showcase\n\n", cipherbird.Version())
	abc := []byte("abc")
	msg := []byte("secret payload")

	fmt.Println("HASHING")
	ck("SHA-256(abc) KAT", cipherbird.Hex(must(cipherbird.SHA256(abc))) ==
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	ck("SHA-512", len(must(cipherbird.SHA512(abc))) == 64)
	ck("BLAKE2b", len(must(cipherbird.Blake2b(abc, nil))) == 64)
	hkey := must(cipherbird.SymKeygen())
	mac := must(cipherbird.HmacSHA512(abc, hkey))
	ck("HMAC-SHA512 verify", cipherbird.HmacSHA512Verify(abc, mac, hkey))
	phc, _ := cipherbird.Argon2idHashStr("hunter2", 2, 67108864)
	ck("Argon2id PHC verify", cipherbird.Argon2idVerifyStr("hunter2", phc))

	fmt.Println("\nSYMMETRIC")
	sk := must(cipherbird.SymKeygen())
	xct := must(cipherbird.XChaCha20Encrypt(msg, sk, nil))
	ck("XChaCha20 round-trip", bytes.Equal(must(cipherbird.XChaCha20Decrypt(xct, sk, nil)), msg))
	if cipherbird.AES256GCMAvailable() {
		act := must(cipherbird.AES256GCMEncrypt(msg, sk, nil))
		ck("AES-256-GCM round-trip", bytes.Equal(must(cipherbird.AES256GCMDecrypt(act, sk, nil)), msg))
	} else {
		fmt.Println("    AES-256-GCM unavailable")
	}

	fmt.Println("\nASYMMETRIC")
	ed := cipherbird.Ed25519Keygen()
	sig := must(cipherbird.Ed25519Sign(abc, ed.Secret))
	ck("Ed25519 sign/verify", cipherbird.Ed25519Verify(abc, sig, ed.Public))
	xa, xb := cipherbird.X25519Keygen(), cipherbird.X25519Keygen()
	ck("X25519 ECDH", bytes.Equal(must(cipherbird.X25519SharedSecret(xa.Secret, xb.Public)),
		must(cipherbird.X25519SharedSecret(xb.Secret, xa.Public))))
	r, s := cipherbird.BoxKeygen(), cipherbird.BoxKeygen()
	bct := must(cipherbird.BoxEncrypt(msg, r.Public, s.Secret))
	ck("Box round-trip", bytes.Equal(must(cipherbird.BoxDecrypt(bct, s.Public, r.Secret)), msg))
	sct := must(cipherbird.SealedBoxEncrypt(msg, r.Public))
	ck("SealedBox round-trip", bytes.Equal(must(cipherbird.SealedBoxDecrypt(sct, r.Public, r.Secret)), msg))

	fmt.Println("\nVAULTS")
	vault, _ := cipherbird.NewVault(must(cipherbird.RandomBytes(32)), 0)
	pkt := mustPkt(vault.Seal(msg, "ctx"))
	ck("SecureVault round-trip", bytes.Equal(must(vault.Open(pkt, "ctx")), msg))
	vault.Close()
	alice, bob := cipherbird.AsymBundleGenerate(), cipherbird.AsymBundleGenerate()
	apkt := mustPkt(cipherbird.AsymVaultSeal(&alice, bob.BoxPublic, msg, "ctx"))
	ck("AsymmetricVault round-trip", bytes.Equal(must(cipherbird.AsymVaultOpen(apkt, &bob, alice.SignPublic, "ctx")), msg))

	fmt.Println("\nPOST-QUANTUM")
	kem := cipherbird.MlKemKeygen(1)
	enc, _ := cipherbird.MlKemEncapsulate(kem.Public, 1)
	ck("ML-KEM-768 encaps/decaps", bytes.Equal(enc.SharedSecret, must(cipherbird.MlKemDecapsulate(enc.Ciphertext, kem.Secret, 1))))
	hkem := cipherbird.HybridKemKeygen()
	henc, _ := cipherbird.HybridKemEncapsulate(hkem.Public)
	ck("Hybrid X25519+ML-KEM-768 encaps/decaps",
		bytes.Equal(henc.SharedSecret, must(cipherbird.HybridKemDecapsulate(henc.Ciphertext, hkem.Secret))) && len(henc.SharedSecret) == 32)
	dsa := cipherbird.MlDsaKeygen(1)
	dsig := must(cipherbird.MlDsaSign(abc, dsa.Secret, 1))
	ck("ML-DSA-65 sign/verify", cipherbird.MlDsaVerify(abc, dsig, dsa.Public, 1))
	slh := cipherbird.SlhDsaKeygen(1, 0)
	ssig := must(cipherbird.SlhDsaSign(abc, slh.Secret, 1, 0))
	ck("SLH-DSA-128f sign/verify", cipherbird.SlhDsaVerify(abc, ssig, slh.Public, 1, 0))

	fmt.Println("\nBLS12-381")
	bls := cipherbird.BlsKeygen()
	bsig := must(cipherbird.BlsSign(abc, bls.Secret))
	ck("BLS sign/verify", cipherbird.BlsVerify(abc, bsig, bls.Public))

	fmt.Println("\nKEYRING")
	factor := must(cipherbird.RandomBytes(32))
	kr := cipherbird.NewKeyring()
	kr.AddDeviceSlot(factor)
	kr.AddPassphraseSlot("cross-device pass", 0)
	blob := must(kr.Serialise())
	kr2, _ := cipherbird.DeserialiseKeyring(blob)
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

func mustPkt(p *cipherbird.Packet, err error) *cipherbird.Packet {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: %v\n", err)
		os.Exit(1)
	}
	return p
}
