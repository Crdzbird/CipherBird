package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"

// ═══════════════════════════════════════════════════════════════════════════════
// ECVRF — Verifiable Random Function (RFC 9381, ECVRF-EDWARDS25519-SHA512-TAI)
//
// A public-key PRF: the secret-key holder maps an input to a unique,
// unpredictable 64-byte output plus an 80-byte proof anyone can verify with the
// public key — without learning the key or being able to forge a different
// output. Verifiable lotteries, proof-of-stake leader election, on-chain
// randomness beacons.
//
//	kp := cryptolib.EcvrfKeygen()
//	pi, _ := cryptolib.EcvrfProve(kp.Secret, alpha)      // prover
//	beta, err := cryptolib.EcvrfVerify(kp.Public, alpha, pi) // verifier: err != nil ⇒ invalid
// ═══════════════════════════════════════════════════════════════════════════════

// EcvrfKeygen generates an ECVRF key pair (pk 32 B, sk = 32-byte seed).
func EcvrfKeygen() KeyPair {
	kp := C.cryptolib_ecvrf_keygen()
	return KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
}

// EcvrfPublicKey derives the public key Y = x·B from a 32-byte secret seed.
func EcvrfPublicKey(sk []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ecvrf_public_key(u8(sk), C.size_t(len(sk))))
}

// EcvrfProve returns the 80-byte proof for (sk, alpha).
func EcvrfProve(sk, alpha []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ecvrf_prove(u8(sk), C.size_t(len(sk)), u8(alpha), C.size_t(len(alpha))))
}

// EcvrfProofToHash returns the 64-byte VRF output beta for a proof.
func EcvrfProofToHash(pi []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ecvrf_proof_to_hash(u8(pi), C.size_t(len(pi))))
}

// EcvrfVerify checks a proof; on success returns the 64-byte beta, otherwise a
// non-nil error (the proof is invalid).
func EcvrfVerify(pk, alpha, pi []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_ecvrf_verify(
		u8(pk), C.size_t(len(pk)), u8(alpha), C.size_t(len(alpha)), u8(pi), C.size_t(len(pi))))
}
