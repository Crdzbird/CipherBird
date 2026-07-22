// CryptoLib for Go — Flagship / Fortress: state-of-the-art sealed messaging.
//
// Two assurance tiers of one construction: encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first.
// Run:  DYLD_LIBRARY_PATH=../../../build/release go run ./sealed   (macOS)
//       LD_LIBRARY_PATH=../../../build/release  go run ./sealed    (Linux)
package main

import (
	"bytes"
	"fmt"
	"os"

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

func demo(tier cl.SealedTier, name, blurb string) {
	fmt.Printf("\n── %s ──  %s\n", name, blurb)

	// Each party is an Identity: a recipient (KEM) keypair to RECEIVE and a sender
	// (signature) keypair to SIGN. Publish the publics, keep the secrets.
	alice, err := cl.NewIdentity(tier)
	if err != nil {
		panic(err)
	}
	bob, _ := cl.NewIdentity(tier)
	opts := &cl.SealOpts{AAD: []byte("thread-42"), Purpose: []byte("secure-note")}

	// One-shot: Bob seals TO Alice, signed by Bob. Confidential while any KEM leg
	// holds; unforgeable unless all signature legs break.
	env, err := bob.Seal([]byte("the eagle lands at dawn"), alice.RecipientPublic, opts)
	if err != nil {
		panic(err)
	}
	pt, err := alice.Open(env, bob.SenderPublic, opts)
	ck("one-shot seal → open round-trips", err == nil && string(pt) == "the eagle lands at dawn")

	// Auth-first: a forged sender is rejected, no plaintext leaks.
	mallory, _ := cl.NewIdentity(tier)
	_, ferr := alice.Open(env, mallory.SenderPublic, opts)
	ck("forged sender rejected (auth-first)", ferr != nil)

	// Inspect + address without any key (routing / relays).
	info, _ := cl.SealedInspect(env)
	ck(fmt.Sprintf("inspect: suite=%d streaming=%v ct=%dB", info.Suite, info.Streaming, info.KemCiphertextLen),
		info.Suite == map[bool]uint8{true: 2, false: 1}[name == "Fortress"] && !info.Streaming)
	ck("addressed to Alice, not Mallory",
		cl.SealedAddressedTo(env, alice.RecipientPublic) && !cl.SealedAddressedTo(env, mallory.RecipientPublic))

	// Streaming: preamble → chunks → signed trailer. Chunks are authenticated
	// immediately; the sender signature is verified at Finalize.
	sealer, err := bob.NewStreamSealer(alice.RecipientPublic, opts)
	if err != nil {
		panic(err)
	}
	preamble, _ := sealer.Preamble()
	parts := []string{"chunk-one ", "chunk-two ", "chunk-three"}
	var wire [][]byte
	for _, p := range parts[:len(parts)-1] {
		ct, _ := sealer.Push([]byte(p))
		wire = append(wire, ct)
	}
	lastCt, trailer, _ := sealer.Finalize([]byte(parts[len(parts)-1]))
	sealer.Close()

	opener, err := alice.NewStreamOpener(preamble, bob.SenderPublic, opts)
	if err != nil {
		panic(err)
	}
	var assembled bytes.Buffer
	for _, ct := range wire {
		p, _, _ := opener.Pull(ct)
		assembled.Write(p)
	}
	p, final, _ := opener.Pull(lastCt)
	assembled.Write(p)
	verr := opener.Finalize(trailer) // verifies whole-stream signature
	opener.Close()
	ck("streaming round-trips + trailer verifies",
		assembled.String() == "chunk-one chunk-two chunk-three" && final && verr == nil)
}

func main() {
	if err := cl.Init(); err != nil {
		panic(err)
	}
	fmt.Printf("CryptoLib %s — Flagship / Fortress (Go)\n", cl.Version())
	demo(cl.Flagship, "Flagship", "X25519+sntrup761 KEM · Ed25519+ML-DSA-65 sig")
	demo(cl.Fortress, "Fortress", "triple KEM (+ML-KEM-768) · triple sig (+SLH-DSA)")

	fmt.Printf("\n%d passed, %d failed — sealed %s\n", pass, fail,
		map[bool]string{true: "OK", false: "FAILED"}[fail == 0])
	if fail != 0 {
		os.Exit(1)
	}
}
