package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"

import "errors"

// ═══════════════════════════════════════════════════════════════════════════════
// OPRF — Oblivious Pseudorandom Function (RFC 9497, ristretto255-SHA-512)
//
// A two-party PRF: the client blinds its input, the server evaluates under its
// key without seeing the input, and the client unblinds to a PRF output. Privacy
// Pass, private set intersection, password hardening, OPAQUE.
//
//	kp, _ := cryptolib.OprfDeriveKeyPair(seed, nil)     // server
//	b, _ := cryptolib.OprfBlindInput(input)             // client: send b.BlindedElement
//	ev, _ := cryptolib.OprfBlindEvaluate(kp.Secret, b.BlindedElement) // server
//	out, _ := cryptolib.OprfFinalize(input, b.Blind, ev)             // client
// ═══════════════════════════════════════════════════════════════════════════════

// OprfBlindResult is the client Blind output: the secret blind + the blinded
// element to send to the server.
type OprfBlindResult struct {
	Blind          []byte
	BlindedElement []byte
}

// OprfDeriveKeyPair derives an OPRF key pair from a seed (+ optional info).
func OprfDeriveKeyPair(seed, info []byte) (KeyPair, error) {
	kp := C.cryptolib_oprf_derive_keypair(u8(seed), C.size_t(len(seed)), u8(info), C.size_t(len(info)))
	pub, sec := goBytes(kp.public_key), goBytes(kp.secret_key)
	if pub == nil || sec == nil {
		return KeyPair{}, errors.New("cryptolib: oprf derive_keypair failed")
	}
	return KeyPair{Public: pub, Secret: sec}, nil
}

func oprfBlindOut(b C.CryptoOprfBlind) (OprfBlindResult, error) {
	if b.error != nil {
		msg := C.GoString(b.error)
		C.cryptolib_oprf_blind_free(&b)
		return OprfBlindResult{}, errors.New(msg)
	}
	defer C.cryptolib_oprf_blind_free(&b)
	return OprfBlindResult{Blind: cbufBytes(b.blind), BlindedElement: cbufBytes(b.blinded_element)}, nil
}

// OprfBlindInput blinds an input with a fresh random scalar (client side).
func OprfBlindInput(input []byte) (OprfBlindResult, error) {
	return oprfBlindOut(C.cryptolib_oprf_blind(u8(input), C.size_t(len(input))))
}

// OprfBlindWithScalar is the deterministic variant (test vectors).
func OprfBlindWithScalar(input, blind []byte) (OprfBlindResult, error) {
	return oprfBlindOut(C.cryptolib_oprf_blind_with_scalar(
		u8(input), C.size_t(len(input)), u8(blind), C.size_t(len(blind))))
}

// OprfBlindEvaluate evaluates a blinded element under the secret key (server side).
func OprfBlindEvaluate(sk, blindedElement []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_oprf_blind_evaluate(
		u8(sk), C.size_t(len(sk)), u8(blindedElement), C.size_t(len(blindedElement))))
}

// OprfFinalize unblinds the evaluated element → 64-byte PRF output (client side).
func OprfFinalize(input, blind, evaluatedElement []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_oprf_finalize(
		u8(input), C.size_t(len(input)), u8(blind), C.size_t(len(blind)),
		u8(evaluatedElement), C.size_t(len(evaluatedElement))))
}

// OprfEvaluate computes the PRF output directly from the key + input (server one-shot).
func OprfEvaluate(sk, input []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_oprf_evaluate(
		u8(sk), C.size_t(len(sk)), u8(input), C.size_t(len(input))))
}
