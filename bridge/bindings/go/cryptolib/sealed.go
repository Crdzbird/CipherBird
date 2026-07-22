package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"runtime"
)

// ═══════════════════════════════════════════════════════════════════════════════
// Flagship / Fortress — state-of-the-art sealed messaging
//
// Two assurance tiers of one construction (encapsulate → sign-then-encrypt inside
// a key-committing cascade, recipient-bound, auth-first). Every message is hybrid
// post-quantum confidential AND authentic; a recipient can't re-forward it as if
// you sent it to someone else. This is a self-contained, drop-in messaging layer.
// ═══════════════════════════════════════════════════════════════════════════════

// SealedTier selects the assurance tier.
type SealedTier int

const (
	// Flagship — X25519+sntrup761 KEM, Ed25519+ML-DSA-65 signature. Recommended default.
	Flagship SealedTier = 0
	// Fortress — adds ML-KEM-768 (triple KEM) + SLH-DSA (triple signature). Maximum
	// assurance: no single cryptanalytic point of failure. Larger and slower.
	Fortress SealedTier = 1
)

// SealOpts are optional per-message bindings. AAD binds arbitrary context into
// the AEAD; Purpose binds a domain label into the signature. Both must match on
// open. A nil *SealOpts means "no AAD, no purpose".
type SealOpts struct {
	AAD     []byte
	Purpose []byte
}

func (o *SealOpts) aad() []byte {
	if o == nil {
		return nil
	}
	return o.AAD
}
func (o *SealOpts) purpose() []byte {
	if o == nil {
		return nil
	}
	return o.Purpose
}

// Identity bundles the two keypairs a party needs: a recipient (KEM) keypair for
// RECEIVING sealed messages, and a sender (signature) keypair for SIGNING what it
// sends. Generate one per party with NewIdentity; publish RecipientPublic and
// SenderPublic, keep the secrets. This is the configuration/setup handle for the
// sealed-messaging API — everything else hangs off it.
type Identity struct {
	Tier            SealedTier
	RecipientPublic []byte
	RecipientSecret []byte
	SenderPublic    []byte
	SenderSecret    []byte
}

// NewIdentity generates a fresh recipient + sender keypair for the given tier.
func NewIdentity(tier SealedTier) (*Identity, error) {
	r := C.cryptolib_sealed_generate_recipient(C.int(tier))
	if r.public_key.data == nil {
		return nil, errors.New("cryptolib: recipient keygen failed")
	}
	s := C.cryptolib_sealed_generate_sender(C.int(tier))
	if s.public_key.data == nil {
		return nil, errors.New("cryptolib: sender keygen failed")
	}
	return &Identity{
		Tier:            tier,
		RecipientPublic: goBytes(r.public_key),
		RecipientSecret: goBytes(r.secret_key),
		SenderPublic:    goBytes(s.public_key),
		SenderSecret:    goBytes(s.secret_key),
	}, nil
}

// Seal signs plaintext with this identity's sender key and encrypts it to
// recipientPublic. Secure while any KEM leg holds; unforgeable unless all
// signature legs break; the recipient is bound so the message can't be re-forwarded.
func (id *Identity) Seal(plaintext, recipientPublic []byte, opts *SealOpts) ([]byte, error) {
	aad, purpose := opts.aad(), opts.purpose()
	return checkBufResult(C.cryptolib_sealed_seal(C.int(id.Tier),
		u8(plaintext), C.size_t(len(plaintext)),
		u8(recipientPublic), C.size_t(len(recipientPublic)),
		u8(id.SenderSecret), C.size_t(len(id.SenderSecret)),
		u8(aad), C.size_t(len(aad)), u8(purpose), C.size_t(len(purpose))))
}

// Open decrypts and then verifies (auth-first) a message sent by senderPublic.
// Returns an error — and no plaintext — if the signature or recipient binding fails.
func (id *Identity) Open(envelope, senderPublic []byte, opts *SealOpts) ([]byte, error) {
	aad, purpose := opts.aad(), opts.purpose()
	return checkBufResult(C.cryptolib_sealed_open(C.int(id.Tier),
		u8(envelope), C.size_t(len(envelope)),
		u8(id.RecipientSecret), C.size_t(len(id.RecipientSecret)),
		u8(id.RecipientPublic), C.size_t(len(id.RecipientPublic)),
		u8(senderPublic), C.size_t(len(senderPublic)),
		u8(aad), C.size_t(len(aad)), u8(purpose), C.size_t(len(purpose))))
}

// ── Inspection (public metadata, no secrets) ──────────────────────────────────

// SealedInfo is the public metadata carried by a sealed envelope.
type SealedInfo struct {
	Version          uint8
	Suite            uint8 // 1 = Flagship, 2 = Fortress
	Streaming        bool
	Fingerprint      [16]byte // BLAKE2b-128 of the recipient public key
	KemCiphertextLen int
}

// SealedInspect reads an envelope's public header without any key or secret.
func SealedInspect(envelope []byte) (*SealedInfo, error) {
	info := C.cryptolib_sealed_inspect(u8(envelope), C.size_t(len(envelope)))
	if info.ok == 0 {
		return nil, errors.New("cryptolib: unrecognizable sealed envelope")
	}
	si := &SealedInfo{
		Version:          uint8(info.version),
		Suite:            uint8(info.suite),
		Streaming:        info.streaming != 0,
		KemCiphertextLen: int(info.kem_ciphertext_len),
	}
	for i := 0; i < 16; i++ {
		si.Fingerprint[i] = byte(info.fingerprint[i])
	}
	return si, nil
}

// SealedAddressedTo reports whether the envelope is addressed to recipientPublic
// (fingerprint match) — routing/addressing without decrypting.
func SealedAddressedTo(envelope, recipientPublic []byte) bool {
	return C.cryptolib_sealed_addressed_to(u8(envelope), C.size_t(len(envelope)),
		u8(recipientPublic), C.size_t(len(recipientPublic))) == 1
}

// ── Streaming (large data / files) ────────────────────────────────────────────

// StreamSealer encrypts a stream: Preamble() once, Push() each chunk, Finalize()
// for the last chunk + signed trailer. Close() when done (also finalized by GC).
type StreamSealer struct{ handle C.CryptoSealedSealer }

// NewStreamSealer begins an encrypting stream to recipientPublic.
func (id *Identity) NewStreamSealer(recipientPublic []byte, opts *SealOpts) (*StreamSealer, error) {
	purpose := opts.purpose()
	var cerr *C.char
	h := C.cryptolib_sealed_sealer_begin(C.int(id.Tier),
		u8(recipientPublic), C.size_t(len(recipientPublic)),
		u8(id.SenderSecret), C.size_t(len(id.SenderSecret)),
		u8(purpose), C.size_t(len(purpose)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	if h == nil {
		return nil, errors.New("cryptolib: stream sealer begin failed")
	}
	s := &StreamSealer{handle: h}
	runtime.SetFinalizer(s, func(s *StreamSealer) { s.Close() })
	return s, nil
}

// Preamble returns the stream header to write/transmit first (KEM ciphertext etc.).
func (s *StreamSealer) Preamble() ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_sealed_sealer_preamble(s.handle))
}

// Push encrypts one interior chunk, returning its ciphertext.
func (s *StreamSealer) Push(chunk []byte) ([]byte, error) {
	defer runtime.KeepAlive(s)
	return checkBufResult(C.cryptolib_sealed_sealer_push(s.handle, u8(chunk), C.size_t(len(chunk))))
}

// Finalize encrypts the final chunk (may be empty) and returns it plus the signed
// trailer (which authenticates the whole stream at the opener's Finalize).
func (s *StreamSealer) Finalize(last []byte) (ciphertext, trailer []byte, err error) {
	defer runtime.KeepAlive(s)
	var tr C.CryptoBuffer
	ct, err := checkBufResult(C.cryptolib_sealed_sealer_finalize(s.handle, u8(last), C.size_t(len(last)), &tr))
	if err != nil {
		return nil, nil, err
	}
	return ct, goBytes(tr), nil
}

// Close frees the native sealer. Safe to call more than once.
func (s *StreamSealer) Close() {
	if s.handle != nil {
		C.cryptolib_sealed_sealer_free(s.handle)
		s.handle = nil
	}
}

// StreamOpener decrypts a stream: Pull() each chunk (final=true on the last),
// then Finalize(trailer) to verify the sender signature over the whole stream.
type StreamOpener struct{ handle C.CryptoSealedOpener }

// NewStreamOpener begins decrypting a stream from senderPublic given its preamble.
func (id *Identity) NewStreamOpener(preamble, senderPublic []byte, opts *SealOpts) (*StreamOpener, error) {
	purpose := opts.purpose()
	var cerr *C.char
	h := C.cryptolib_sealed_opener_begin(C.int(id.Tier),
		u8(preamble), C.size_t(len(preamble)),
		u8(id.RecipientSecret), C.size_t(len(id.RecipientSecret)),
		u8(id.RecipientPublic), C.size_t(len(id.RecipientPublic)),
		u8(senderPublic), C.size_t(len(senderPublic)),
		u8(purpose), C.size_t(len(purpose)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	if h == nil {
		return nil, errors.New("cryptolib: stream opener begin failed")
	}
	o := &StreamOpener{handle: h}
	runtime.SetFinalizer(o, func(o *StreamOpener) { o.Close() })
	return o, nil
}

// Pull decrypts one ciphertext chunk. final is true on the terminating chunk.
func (o *StreamOpener) Pull(ct []byte) (plaintext []byte, final bool, err error) {
	defer runtime.KeepAlive(o)
	var f C.int
	pt, err := checkBufResult(C.cryptolib_sealed_opener_pull(o.handle, u8(ct), C.size_t(len(ct)), &f))
	if err != nil {
		return nil, false, err
	}
	return pt, f == 1, nil
}

// Finalize verifies the sender signature over the whole stream. Only valid after
// the final chunk has been pulled (guards against truncation).
func (o *StreamOpener) Finalize(trailer []byte) error {
	defer runtime.KeepAlive(o)
	_, err := checkBufResult(C.cryptolib_sealed_opener_finalize(o.handle, u8(trailer), C.size_t(len(trailer))))
	return err
}

// Close frees the native opener. Safe to call more than once.
func (o *StreamOpener) Close() {
	if o.handle != nil {
		C.cryptolib_sealed_opener_free(o.handle)
		o.handle = nil
	}
}
