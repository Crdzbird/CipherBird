// CryptoLib for Go — Recipes: composition in practice.
//
// Real-world flows that snap primitives together (no new crypto, just wiring).
// Run:  DYLD_LIBRARY_PATH=../../../build/release go run ./recipes   (macOS)
//       LD_LIBRARY_PATH=../../../build/release  go run ./recipes    (Linux)
//
// (Shamir threshold splitting is C++-only — not in the C ABI — so this mirrors
// the other five recipes; see example/recipes.cpp for all six.)
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	cl "github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
)

var pass, fail int

func ck(name string, ok bool) {
	mark := "✓"
	if !ok {
		mark = "✗"
		fail++
	} else {
		pass++
	}
	fmt.Printf("   %s %s\n", mark, name)
}
func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	if err := cl.Init(); err != nil {
		panic(err)
	}
	fmt.Printf("CryptoLib %s — Recipes (Go)\n", cl.Version())
	aad := []byte("recipe/v1")

	// 1. File-as-key vault: deterministic media entropy → master → MolecularVault.
	fmt.Println("\n1. File-as-key vault  (media entropy → MolecularVault)")
	{
		tmp := filepath.Join(os.TempDir(), "cryptolib_go_recipe_key.bin")
		buf := make([]byte, 4096)
		for i := range buf {
			buf[i] = byte(i*37 + 11)
		}
		_ = os.WriteFile(tmp, buf, 0o600)
		defer os.Remove(tmp)

		e1 := mustEntropy(cl.EntropyFromFileDeterministic(tmp))
		master := e1.DeriveAll().VaultMasterKey
		e1.Close()
		env := must(cl.MolecularSealWithKey([]byte("launch codes"), master, aad))

		e2 := mustEntropy(cl.EntropyFromFileDeterministic(tmp))
		master2 := e2.DeriveAll().VaultMasterKey
		e2.Close()
		ck("same file re-derives the key and opens the vault",
			bytes.Equal(must(cl.MolecularOpenWithKey(env, master2, aad)), []byte("launch codes")))
	}

	// 2. Post-quantum message: hybrid KEM shared secret → MolecularVault.
	fmt.Println("\n2. Post-quantum message  (hybrid KEM → MolecularVault)")
	{
		bob := cl.HybridKemKeygen()
		enc, err := cl.HybridKemEncapsulate(bob.Public) // sender
		if err != nil {
			panic(err)
		}
		env := must(cl.MolecularSealWithKey([]byte("see you at dawn"), enc.SharedSecret, aad))
		ss := must(cl.HybridKemDecapsulate(enc.Ciphertext, bob.Secret)) // recipient
		ck("hybrid-KEM secret opens the PQ-sealed message",
			bytes.Equal(must(cl.MolecularOpenWithKey(env, ss, aad)), []byte("see you at dawn")))
	}

	// 3. Sign-then-seal: hybrid signature carried inside a MolecularVault.
	fmt.Println("\n3. Sign-then-seal  (hybrid signature inside MolecularVault)")
	{
		signer := cl.HybridSigKeygen()
		msg := []byte("transfer 100 to acct #42")
		sig := must(cl.HybridSigSign(msg, signer.Secret))
		bundle := append(append([]byte(nil), msg...), sig...)
		env := must(cl.MolecularSeal(bundle, "outer passphrase", aad, 2, 1<<20))
		opened := must(cl.MolecularOpen(env, "outer passphrase", aad))
		gotMsg, gotSig := opened[:len(msg)], opened[len(msg):]
		ck("opened → both Ed25519 and ML-DSA signatures verify",
			cl.HybridSigVerify(gotMsg, gotSig, signer.Public) && bytes.Equal(gotMsg, msg))
	}

	// 4. EVM wallet: secp256k1 → Keccak address → sign tx digest → ecrecover.
	fmt.Println("\n4. EVM wallet  (secp256k1 → Keccak address → sign → ecrecover)")
	{
		w := cl.Secp256k1Keygen()
		addr := must(cl.Keccak256(w.Public[1:]))[12:32] // last 20 bytes
		fmt.Printf("      address 0x%s\n", hex.EncodeToString(addr))
		digest := must(cl.Keccak256([]byte("transfer 1 ETH → 0xBEEF")))
		sig := must(cl.Secp256k1Sign(digest, w.Secret)) // 65B r‖s‖v
		recovered := must(cl.Secp256k1Recover(digest, sig))
		ck("ecrecover returns the signer public key (65B, v included)",
			len(sig) == 65 && bytes.Equal(recovered, w.Public))
	}

	// 5. Keyring-guarded vault: master under device + passphrase → MolecularVault.
	fmt.Println("\n5. Keyring-guarded vault  (Keyring unlock → MolecularVault key)")
	{
		deviceKey := must(cl.RandomBytes(32))
		kr := cl.NewKeyring()
		kr.AddDeviceSlot(deviceKey)
		kr.AddPassphraseSlot("cross-device pass", 0)
		blob := must(kr.Serialise())
		kr2, err := cl.DeserialiseKeyring(blob)
		if err != nil {
			panic(err)
		}
		master := must(kr2.UnlockWithDevice(deviceKey))
		env := must(cl.MolecularSealWithKey([]byte("root secret"), master, aad))
		master2 := must(kr2.UnlockWithPassphrase("cross-device pass"))
		ck("either keyring factor unlocks the same MolecularVault master",
			bytes.Equal(must(cl.MolecularOpenWithKey(env, master2, aad)), []byte("root secret")) &&
				bytes.Equal(master, master2))
		kr.Close()
		kr2.Close()
	}

	fmt.Printf("\n%d passed, %d failed — recipes %s\n", pass, fail,
		map[bool]string{true: "OK", false: "FAILED"}[fail == 0])
	if fail != 0 {
		os.Exit(1)
	}
}

func mustEntropy(e *cl.Entropy, err error) *cl.Entropy {
	if err != nil {
		panic(err)
	}
	return e
}
