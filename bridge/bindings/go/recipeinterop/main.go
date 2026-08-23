// Cross-language Recipe interop: seal a fixed set of configurations to a
// directory, or open and verify them.
//
//	go run ./recipeinterop seal|open <dir>
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
)

// Fixed inputs so every language derives identical keys.
const (
	keyHex     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	skHex      = "d463cb8e5a1b8f2e6c4a90f37d215e08b9c6a4713f2085dcae6b19347c50f2a6"
	passphrase = "interop passphrase"
	plaintext  = "cross-language recipe envelope"
)

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func configs(pk, sk []byte) []struct {
	name string
	r    *cryptolib.Recipe
} {
	return []struct {
		name string
		r    *cryptolib.Recipe
	}{
		{"balanced", cryptolib.NewRecipe(cryptolib.ProfileBalanced).WithKey(mustHex(keyHex))},
		{"maximum", cryptolib.NewRecipe(cryptolib.ProfileMaximum).WithKey(mustHex(keyHex))},
		{"signed", cryptolib.NewRecipe(cryptolib.ProfileHigh).WithKey(mustHex(keyHex)).
			SignedBy(sk, cryptolib.SigEd25519).VerifiedBy(pk)},
		{"passphrase", cryptolib.NewRecipe(cryptolib.ProfileBalanced).
			WithPassphrase(passphrase).Argon2Cost(1, 8*1024*1024)},
		{"fec", cryptolib.NewRecipe(cryptolib.ProfileBalanced).
			WithKey(mustHex(keyHex)).WithFec(cryptolib.FecRepetition3)},
	}
}

func main() {
	if err := cryptolib.Init(); err != nil {
		panic(err)
	}
	mode, dir := os.Args[1], os.Args[2]
	kp := cryptolib.Ed25519KeygenFromSeed(mustHex(skHex))
	pk, sk := kp.Public, kp.Secret
	failures := 0

	for _, c := range configs(pk, sk) {
		path := fmt.Sprintf("%s/%s.bin", dir, c.name)
		if mode == "seal" {
			env, err := c.r.Seal([]byte(plaintext))
			if err != nil {
				fmt.Printf(" FAIL  go seals %s: %v\n", c.name, err)
				failures++
				continue
			}
			if err := os.WriteFile(path, env, 0o600); err != nil {
				panic(err)
			}
		} else {
			raw, err := os.ReadFile(path)
			if err != nil {
				fmt.Printf(" FAIL  go opens %s: %v\n", c.name, err)
				failures++
				continue
			}
			got, err := c.r.Open(raw)
			ok := err == nil && string(got) == plaintext
			if ok {
				fmt.Printf("  ok   go opens %s\n", c.name)
			} else {
				fmt.Printf(" FAIL  go opens %s: %v\n", c.name, err)
				failures++
			}
		}
	}
	if mode == "seal" {
		fmt.Printf("  go sealed %d envelopes\n", len(configs(pk, sk)))
	}
	if failures > 0 {
		os.Exit(1)
	}
}
