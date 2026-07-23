package cryptolib

/*
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// ═══════════════════════════════════════════════════════════════════════════════
// BBS Signatures — multi-message signatures + zero-knowledge selective disclosure
// (draft-irtf-cfrg-bbs-signatures, BLS12-381-SHA-256).
//
// A signer signs a vector of messages; the holder derives a proof revealing only
// a chosen subset while proving a valid signature covers ALL of them — the core
// primitive behind anonymous credentials (W3C Verifiable Credentials).
//
//	kp, _ := cryptolib.BbsKeygen(keyMaterial, nil)
//	sig, _ := cryptolib.BbsSign(kp.Secret, kp.Public, header, messages)
//	proof, _ := cryptolib.BbsProofGen(kp.Public, sig, header, ph, messages, []uint64{0, 3})
//	ok := cryptolib.BbsProofVerify(kp.Public, proof, header, ph, revealed, []uint64{0, 3})
// ═══════════════════════════════════════════════════════════════════════════════

// idxSlice marshals a []uint64 into a C uint64 array (nil for empty).
func idxSlice(idx []uint64) (*C.uint64_t, []C.uint64_t) {
	if len(idx) == 0 {
		return nil, nil
	}
	arr := make([]C.uint64_t, len(idx))
	for i, v := range idx {
		arr[i] = C.uint64_t(v)
	}
	return (*C.uint64_t)(unsafe.Pointer(&arr[0])), arr
}

// BbsKeygen derives a key pair from key material (>= 32 bytes) + optional key info.
func BbsKeygen(keyMaterial, keyInfo []byte) (KeyPair, error) {
	kp := C.cryptolib_bbs_keygen(u8(keyMaterial), C.size_t(len(keyMaterial)), u8(keyInfo), C.size_t(len(keyInfo)))
	pub, sec := goBytes(kp.public_key), goBytes(kp.secret_key)
	if pub == nil || sec == nil {
		return KeyPair{}, errors.New("cryptolib: bbs keygen failed (key material must be >= 32 bytes)")
	}
	return KeyPair{Public: pub, Secret: sec}, nil
}

// BbsSkToPk derives the 96-byte public key from a 32-byte secret key.
func BbsSkToPk(sk []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_bbs_sk_to_pk(u8(sk), C.size_t(len(sk))))
}

// BbsSign signs a vector of messages → 80-byte signature.
func BbsSign(sk, pk, header []byte, messages [][]byte) ([]byte, error) {
	mp, ml, free := cByteSlices(messages)
	defer free()
	return checkBufResult(C.cryptolib_bbs_sign(
		u8(sk), C.size_t(len(sk)), u8(pk), C.size_t(len(pk)), u8(header), C.size_t(len(header)),
		mp, ml, C.size_t(len(messages))))
}

// BbsVerify verifies a signature over a vector of messages.
func BbsVerify(pk, signature, header []byte, messages [][]byte) bool {
	mp, ml, free := cByteSlices(messages)
	defer free()
	return C.cryptolib_bbs_verify(
		u8(pk), C.size_t(len(pk)), u8(signature), C.size_t(len(signature)), u8(header), C.size_t(len(header)),
		mp, ml, C.size_t(len(messages))) == 1
}

// BbsProofGen derives a selective-disclosure proof. `messages` is the FULL signed
// vector; `disclosedIndexes` (0-based) selects which to reveal.
func BbsProofGen(pk, signature, header, ph []byte, messages [][]byte, disclosedIndexes []uint64) ([]byte, error) {
	mp, ml, free := cByteSlices(messages)
	defer free()
	ip, keep := idxSlice(disclosedIndexes)
	_ = keep
	return checkBufResult(C.cryptolib_bbs_proof_gen(
		u8(pk), C.size_t(len(pk)), u8(signature), C.size_t(len(signature)),
		u8(header), C.size_t(len(header)), u8(ph), C.size_t(len(ph)),
		mp, ml, C.size_t(len(messages)), ip, C.size_t(len(disclosedIndexes))))
}

// BbsProofVerify verifies a selective-disclosure proof. `disclosedMessages` are
// the revealed messages, aligned with `disclosedIndexes`.
func BbsProofVerify(pk, proof, header, ph []byte, disclosedMessages [][]byte, disclosedIndexes []uint64) bool {
	mp, ml, free := cByteSlices(disclosedMessages)
	defer free()
	ip, keep := idxSlice(disclosedIndexes)
	_ = keep
	return C.cryptolib_bbs_proof_verify(
		u8(pk), C.size_t(len(pk)), u8(proof), C.size_t(len(proof)),
		u8(header), C.size_t(len(header)), u8(ph), C.size_t(len(ph)),
		mp, ml, C.size_t(len(disclosedMessages)), ip, C.size_t(len(disclosedIndexes))) == 1
}
