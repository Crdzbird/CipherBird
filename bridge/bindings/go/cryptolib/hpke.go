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
// HPKE — Hybrid Public Key Encryption (RFC 9180)
//
// The standardized public-key encryption used by TLS ECH, MLS, and Oblivious
// HTTP. KEM is DHKEM(X25519, HKDF-SHA256); an envelope sealed here opens in any
// conformant HPKE implementation. Suites are chosen with the Hpke* selector
// constants below.
//
//	bob := cryptolib.HpkeKeygen()
//	enc, ct, _ := cryptolib.HpkeSealBase(cryptolib.HpkeKdfSha256,
//	    cryptolib.HpkeAeadChaCha20Poly1305, bob.Public, info, aad, plaintext)
//	pt, _ := cryptolib.HpkeOpenBase(cryptolib.HpkeKdfSha256,
//	    cryptolib.HpkeAeadChaCha20Poly1305, enc, bob.Secret, info, aad, ct)
// ═══════════════════════════════════════════════════════════════════════════════

// KDF selectors.
const (
	HpkeKdfSha256 = 1
	HpkeKdfSha512 = 3
)

// AEAD selectors.
const (
	HpkeAeadAes128Gcm        = 1
	HpkeAeadAes256Gcm        = 2
	HpkeAeadChaCha20Poly1305 = 3
	HpkeAeadExportOnly       = 0xFFFF
)

// Mode selectors.
const (
	HpkeModeBase    = 0
	HpkeModePsk     = 1
	HpkeModeAuth    = 2
	HpkeModeAuthPsk = 3
)

// HpkeContext is an established one-directional HPKE context. Not safe for
// concurrent use; Close when done (a finalizer is a backstop).
type HpkeContext struct{ handle C.CryptoHpkeContext }

func wrapHpke(h C.CryptoHpkeContext) *HpkeContext {
	c := &HpkeContext{handle: h}
	runtime.SetFinalizer(c, func(c *HpkeContext) { c.Close() })
	return c
}

// HpkeSender bundles the KEM encapsulation (send to the receiver) and the
// sender's context.
type HpkeSender struct {
	Enc     []byte
	Context *HpkeContext
}

// HpkeKeygen generates a fresh X25519 key pair for HPKE.
func HpkeKeygen() KeyPair {
	kp := C.cryptolib_hpke_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// HpkeDeriveKeyPair deterministically derives a key pair from input keying
// material (DHKEM(X25519).DeriveKeyPair).
func HpkeDeriveKeyPair(ikm []byte) KeyPair {
	kp := C.cryptolib_hpke_derive_keypair(u8(ikm), C.size_t(len(ikm)))
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// HpkeSetupS runs the sender key schedule for any mode. Pass nil for the
// psk/pskID/skS arguments a mode does not use.
func HpkeSetupS(kdf, aead, mode int, pkR, info, psk, pskID, skS []byte) (*HpkeSender, error) {
	var enc C.CryptoBuffer
	var cerr *C.char
	h := C.cryptolib_hpke_setup_s(C.int(kdf), C.int(aead), C.int(mode),
		u8(pkR), C.size_t(len(pkR)), u8(info), C.size_t(len(info)),
		u8(psk), C.size_t(len(psk)), u8(pskID), C.size_t(len(pskID)),
		u8(skS), C.size_t(len(skS)), &enc, &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	if h == nil {
		return nil, errors.New("cryptolib: hpke setup_s failed")
	}
	return &HpkeSender{Enc: goBytes(enc), Context: wrapHpke(h)}, nil
}

// HpkeSetupR runs the receiver key schedule for any mode. Pass nil for the
// psk/pskID/pkS arguments a mode does not use.
func HpkeSetupR(kdf, aead, mode int, enc, skR, info, psk, pskID, pkS []byte) (*HpkeContext, error) {
	var cerr *C.char
	h := C.cryptolib_hpke_setup_r(C.int(kdf), C.int(aead), C.int(mode),
		u8(enc), C.size_t(len(enc)), u8(skR), C.size_t(len(skR)), u8(info), C.size_t(len(info)),
		u8(psk), C.size_t(len(psk)), u8(pskID), C.size_t(len(pskID)),
		u8(pkS), C.size_t(len(pkS)), &cerr)
	if cerr != nil {
		msg := C.GoString(cerr)
		C.cryptolib_str_free(cerr)
		return nil, errors.New(msg)
	}
	if h == nil {
		return nil, errors.New("cryptolib: hpke setup_r failed")
	}
	return wrapHpke(h), nil
}

// Seal (sender) AEAD-encrypts the next message, advancing the sequence.
func (c *HpkeContext) Seal(aad, pt []byte) ([]byte, error) {
	defer runtime.KeepAlive(c)
	return checkBufResult(C.cryptolib_hpke_seal(c.handle,
		u8(aad), C.size_t(len(aad)), u8(pt), C.size_t(len(pt))))
}

// Open (receiver) AEAD-decrypts the next message, advancing the sequence.
func (c *HpkeContext) Open(aad, ct []byte) ([]byte, error) {
	defer runtime.KeepAlive(c)
	return checkBufResult(C.cryptolib_hpke_open(c.handle,
		u8(aad), C.size_t(len(aad)), u8(ct), C.size_t(len(ct))))
}

// Export derives a length-byte secret bound to this context (RFC 9180 §5.3).
func (c *HpkeContext) Export(exporterContext []byte, length int) ([]byte, error) {
	defer runtime.KeepAlive(c)
	return checkBufResult(C.cryptolib_hpke_export(c.handle,
		u8(exporterContext), C.size_t(len(exporterContext)), C.size_t(length)))
}

// Close releases the context (zeroises key material).
func (c *HpkeContext) Close() {
	if c.handle != nil {
		C.cryptolib_hpke_context_free(c.handle)
		c.handle = nil
	}
}

// HpkeSealBase is single-shot base-mode encryption: returns (enc, ciphertext).
func HpkeSealBase(kdf, aead int, pkR, info, aad, pt []byte) (enc, ct []byte, err error) {
	s, err := HpkeSetupS(kdf, aead, HpkeModeBase, pkR, info, nil, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	defer s.Context.Close()
	ct, err = s.Context.Seal(aad, pt)
	if err != nil {
		return nil, nil, err
	}
	return s.Enc, ct, nil
}

// HpkeOpenBase is single-shot base-mode decryption.
func HpkeOpenBase(kdf, aead int, enc, skR, info, aad, ct []byte) ([]byte, error) {
	r, err := HpkeSetupR(kdf, aead, HpkeModeBase, enc, skR, info, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.Open(aad, ct)
}
