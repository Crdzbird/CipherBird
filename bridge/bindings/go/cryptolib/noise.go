package cryptolib

/*
#include "cryptolib_c.h"
*/
import "C"

import "errors"

// ═══════════════════════════════════════════════════════════════════════════════
// Incremental BLAKE3 + Noise XX secure channel.
// ═══════════════════════════════════════════════════════════════════════════════

// Blake3Hasher hashes data incrementally. Use it when the input arrives in
// pieces or is too large to hold at once; the digest equals Blake3 over the
// concatenation. Not thread-safe — one hasher per goroutine. Call Close.
type Blake3Hasher struct {
	handle C.CryptoBlake3Handle
}

// NewBlake3Hasher creates a plain hasher. Pass a 32-byte key for keyed (MAC)
// mode, or nil for unkeyed.
func NewBlake3Hasher(key []byte) (*Blake3Hasher, error) {
	if key != nil && len(key) != 32 {
		return nil, errors.New("cryptolib: BLAKE3 key must be exactly 32 bytes")
	}
	h := C.cryptolib_blake3_hasher_create(u8(key), C.size_t(len(key)))
	if h == nil {
		return nil, errors.New("cryptolib: blake3 hasher create failed (BLAKE3 not enabled?)")
	}
	return &Blake3Hasher{handle: h}, nil
}

// Update feeds bytes into the hasher. Fails after Finalize.
func (b *Blake3Hasher) Update(data []byte) error {
	if C.cryptolib_blake3_hasher_update(b.handle, u8(data), C.size_t(len(data))) != 1 {
		return errors.New("cryptolib: blake3 update failed (closed or finalized?)")
	}
	return nil
}

// Finalize produces the digest. outLen 0 means 32 bytes; larger values use
// BLAKE3's extendable output. The hasher accepts no further updates.
func (b *Blake3Hasher) Finalize(outLen int) ([]byte, error) {
	return checkBufResult(C.cryptolib_blake3_hasher_finalize(b.handle, C.size_t(outLen)))
}

// Close releases the native handle. Idempotent.
func (b *Blake3Hasher) Close() {
	if b.handle != nil {
		C.cryptolib_blake3_hasher_free(b.handle)
		b.handle = nil
	}
}

// Noise is a Noise_XX_25519_ChaChaPoly_SHA256 state: first a handshake, then
// after Split a transport channel with mutual static-key authentication and
// forward secrecy.
//
// Handshake: the initiator WriteMessage(0), the responder ReadMessage then
// WriteMessage(1), the initiator ReadMessage then WriteMessage(2), the
// responder ReadMessage. Then both call Split. Handles are NOT thread-safe
// (except DecryptAt, see there). Call Close.
//
//	ini, _ := cryptolib.NewNoise(true, iks.Public, iks.Secret, nil)
//	res, _ := cryptolib.NewNoise(false, rks.Public, rks.Secret, nil)
//	m0, _ := ini.WriteMessage(nil); res.ReadMessage(m0)
//	m1, _ := res.WriteMessage(nil); ini.ReadMessage(m1)
//	m2, _ := ini.WriteMessage(nil); res.ReadMessage(m2)
//	ini.Split(); res.Split()
//	ct, _ := ini.Encrypt([]byte("hi"), nil); pt, _ := res.Decrypt(ct, nil)
type Noise struct {
	handle C.CryptoNoiseHandle
}

// NewNoise creates a Noise XX state. staticPublic/staticSecret are this
// side's X25519 keypair (see X25519Keygen). prologue may be nil; both sides
// must use identical bytes.
func NewNoise(initiator bool, staticPublic, staticSecret, prologue []byte) (*Noise, error) {
	if len(staticPublic) != 32 || len(staticSecret) != 32 {
		return nil, errors.New("cryptolib: Noise static keys must be 32 bytes each")
	}
	init := C.int(0)
	if initiator {
		init = 1
	}
	h := C.cryptolib_noise_create(init,
		u8(staticPublic), C.size_t(len(staticPublic)),
		u8(staticSecret), C.size_t(len(staticSecret)),
		u8(prologue), C.size_t(len(prologue)))
	if h == nil {
		return nil, errors.New("cryptolib: noise create failed")
	}
	return &Noise{handle: h}, nil
}

// WriteMessage produces the next handshake message on this side's turn,
// embedding an optional payload.
func (n *Noise) WriteMessage(payload []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_write_message(n.handle, u8(payload), C.size_t(len(payload))))
}

// ReadMessage consumes the peer's handshake message and returns its payload.
func (n *Noise) ReadMessage(message []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_read_message(n.handle, u8(message), C.size_t(len(message))))
}

// HandshakeFinished reports whether all three handshake messages are done.
func (n *Noise) HandshakeFinished() bool {
	return C.cryptolib_noise_handshake_finished(n.handle) == 1
}

// HandshakeHash is the 32-byte channel-binding value both sides agree on
// once the handshake completes.
func (n *Noise) HandshakeHash() ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_handshake_hash(n.handle))
}

// RemoteStatic is the peer's static X25519 public key learned during the
// handshake. Pin or verify it to prevent an active MITM.
func (n *Noise) RemoteStatic() ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_remote_static(n.handle))
}

// Split derives the transport cipher states (Noise Split). Fails if the
// handshake is unfinished or Split already ran.
func (n *Noise) Split() error {
	if C.cryptolib_noise_split(n.handle) != 1 {
		return errors.New("cryptolib: noise split failed (handshake unfinished or already split)")
	}
	return nil
}

// Encrypt seals one transport record (after Split).
func (n *Noise) Encrypt(plaintext, ad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_encrypt(n.handle,
		u8(plaintext), C.size_t(len(plaintext)), u8(ad), C.size_t(len(ad))))
}

// Decrypt opens the next transport record in sequence (after Split).
func (n *Noise) Decrypt(ciphertext, ad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_decrypt(n.handle,
		u8(ciphertext), C.size_t(len(ciphertext)), u8(ad), C.size_t(len(ad))))
}

// DecryptAt opens the record that was sent at nonceCounter without advancing
// the session's own counter, so several records can be opened concurrently
// on one handle.
//
// The caller must assign each record the counter its sender used (counting
// from 0 per direction), open each counter at most once, and reassemble in
// order — statelessly a replay is indistinguishable from a fresh record. Do
// not run it concurrently with Encrypt/Decrypt on the same handle, which
// mutate the session.
//
// There is deliberately no explicit-nonce Encrypt: sealing twice under one
// (key, counter) leaks the plaintext XOR and the Poly1305 key.
func (n *Noise) DecryptAt(nonceCounter uint64, ciphertext, ad []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_noise_decrypt_at(n.handle, C.uint64_t(nonceCounter),
		u8(ciphertext), C.size_t(len(ciphertext)), u8(ad), C.size_t(len(ad))))
}

// Close releases the native handle. Idempotent.
func (n *Noise) Close() {
	if n.handle != nil {
		C.cryptolib_noise_free(n.handle)
		n.handle = nil
	}
}
