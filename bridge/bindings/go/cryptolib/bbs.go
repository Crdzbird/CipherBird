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

// ── Per-verifier pseudonyms + blind issuance (draft-irtf-cfrg-bbs-per-verifier-
// linkability-02). The pseudonym ciphersuite is applied internally. Scalar
// inputs (proverNyms, nymSecrets, secretProverBlind, signerNymEntropy) are
// 32-byte big-endian. ──────────────────────────────────────────────────────

// BbsCommitWithNym commits to committedMsgs plus proverNyms (secret scalars the
// issuer must not learn). Returns (commitmentWithProof, secretProverBlind).
func BbsCommitWithNym(committedMsgs, proverNyms [][]byte) ([]byte, []byte, error) {
	cm, cl, freeC := cByteSlices(committedMsgs)
	defer freeC()
	pm, pl, freeP := cByteSlices(proverNyms)
	defer freeP()
	var spb C.CryptoBuffer
	cwp, err := checkBufResult(C.cryptolib_bbs_commit_with_nym(
		cm, cl, C.size_t(len(committedMsgs)), pm, pl, C.size_t(len(proverNyms)), &spb))
	if err != nil {
		C.cryptolib_buffer_free(&spb)
		return nil, nil, err
	}
	// goBytes frees spb internally — do not free it again.
	return cwp, goBytes(spb), nil
}

// BbsBlindSignWithNym signs over the commitment + signer messages, folding
// signerNymEntropy into the last nym slot. Returns an 80-byte signature.
func BbsBlindSignWithNym(sk, pk, commitmentWithProof, header []byte, messages [][]byte,
	signerNymEntropy []byte, lengthNymVector uint64) ([]byte, error) {
	mp, ml, free := cByteSlices(messages)
	defer free()
	return checkBufResult(C.cryptolib_bbs_blind_sign_with_nym(
		u8(sk), C.size_t(len(sk)), u8(pk), C.size_t(len(pk)),
		u8(commitmentWithProof), C.size_t(len(commitmentWithProof)),
		u8(header), C.size_t(len(header)),
		mp, ml, C.size_t(len(messages)),
		u8(signerNymEntropy), C.size_t(len(signerNymEntropy)), C.uint64_t(lengthNymVector)))
}

// BbsFinalizeNymSecrets returns the nym_secrets (proverNyms with the last
// element += signerNymEntropy) as concatenated 32-byte scalars.
func BbsFinalizeNymSecrets(proverNyms [][]byte, signerNymEntropy []byte) ([]byte, error) {
	pm, pl, free := cByteSlices(proverNyms)
	defer free()
	return checkBufResult(C.cryptolib_bbs_finalize_nym_secrets(
		pm, pl, C.size_t(len(proverNyms)), u8(signerNymEntropy), C.size_t(len(signerNymEntropy))))
}

// BbsCalculatePseudonym derives the deterministic pseudonym (48-byte compressed
// G1 point) for a context from the nymSecrets.
func BbsCalculatePseudonym(contextID []byte, nymSecrets [][]byte) ([]byte, error) {
	nm, nl, free := cByteSlices(nymSecrets)
	defer free()
	return checkBufResult(C.cryptolib_bbs_calculate_pseudonym(
		u8(contextID), C.size_t(len(contextID)), nm, nl, C.size_t(len(nymSecrets))))
}

// BbsProofGenWithPseudonym generates a pseudonym-bound selective-disclosure
// proof. Returns (proof, pseudonym). The disclosed index lists are 0-based into
// the signer and committed message vectors respectively.
func BbsProofGenWithPseudonym(pk, signature, header, ph, contextID []byte,
	signerMsgs, committedMsgs [][]byte, secretProverBlind []byte, nymSecrets [][]byte,
	disclosedSignerIndexes, disclosedCommittedIndexes []uint64) ([]byte, []byte, error) {
	sm, sl, freeS := cByteSlices(signerMsgs)
	defer freeS()
	cm, cl, freeC := cByteSlices(committedMsgs)
	defer freeC()
	nm, nl, freeN := cByteSlices(nymSecrets)
	defer freeN()
	si, keepS := idxSlice(disclosedSignerIndexes)
	ci, keepC := idxSlice(disclosedCommittedIndexes)
	_, _ = keepS, keepC
	var nymOut C.CryptoBuffer
	proof, err := checkBufResult(C.cryptolib_bbs_proof_gen_with_pseudonym(
		u8(pk), C.size_t(len(pk)), u8(signature), C.size_t(len(signature)),
		u8(header), C.size_t(len(header)), u8(ph), C.size_t(len(ph)),
		u8(contextID), C.size_t(len(contextID)),
		sm, sl, C.size_t(len(signerMsgs)), cm, cl, C.size_t(len(committedMsgs)),
		u8(secretProverBlind), C.size_t(len(secretProverBlind)),
		nm, nl, C.size_t(len(nymSecrets)),
		si, C.size_t(len(disclosedSignerIndexes)), ci, C.size_t(len(disclosedCommittedIndexes)), &nymOut))
	if err != nil {
		C.cryptolib_buffer_free(&nymOut)
		return nil, nil, err
	}
	// goBytes frees nymOut internally — do not free it again.
	return proof, goBytes(nymOut), nil
}

// BbsProofVerifyWithPseudonym verifies a pseudonym-bound proof. disclosedMessages
// and disclosedIndexes are the COMBINED signer+committed disclosures (committed
// index j passed as j+L+1).
func BbsProofVerifyWithPseudonym(pk, proof, header, ph, contextID, pseudonym []byte,
	L, lengthNymVector uint64, disclosedMessages [][]byte, disclosedIndexes []uint64) bool {
	mp, ml, free := cByteSlices(disclosedMessages)
	defer free()
	ip, keep := idxSlice(disclosedIndexes)
	_ = keep
	return C.cryptolib_bbs_proof_verify_with_pseudonym(
		u8(pk), C.size_t(len(pk)), u8(proof), C.size_t(len(proof)),
		u8(header), C.size_t(len(header)), u8(ph), C.size_t(len(ph)),
		u8(contextID), C.size_t(len(contextID)), u8(pseudonym), C.size_t(len(pseudonym)),
		C.uint64_t(L), C.uint64_t(lengthNymVector),
		mp, ml, C.size_t(len(disclosedMessages)), ip, C.size_t(len(disclosedIndexes))) == 1
}

// ── Standalone blind issuance (draft-irtf-cfrg-bbs-blind-signatures-02, no
// pseudonyms). The blind-interface ciphersuite is applied internally.
// secretProverBlind is a 32-byte big-endian scalar. ─────────────────────────

// BbsBlindCommit commits to committedMsgs (which the signer never learns).
// Returns (commitmentWithProof, secretProverBlind).
func BbsBlindCommit(committedMsgs [][]byte) ([]byte, []byte, error) {
	cm, cl, free := cByteSlices(committedMsgs)
	defer free()
	var spb C.CryptoBuffer
	cwp, err := checkBufResult(C.cryptolib_bbs_blind_commit(cm, cl, C.size_t(len(committedMsgs)), &spb))
	if err != nil {
		C.cryptolib_buffer_free(&spb)
		return nil, nil, err
	}
	// goBytes frees spb internally — do not free it again.
	return cwp, goBytes(spb), nil
}

// BbsBlindSign blind-signs over the commitment + signer messages → 80-byte sig.
func BbsBlindSign(sk, pk, commitmentWithProof, header []byte, messages [][]byte) ([]byte, error) {
	mp, ml, free := cByteSlices(messages)
	defer free()
	return checkBufResult(C.cryptolib_bbs_blind_sign(
		u8(sk), C.size_t(len(sk)), u8(pk), C.size_t(len(pk)),
		u8(commitmentWithProof), C.size_t(len(commitmentWithProof)),
		u8(header), C.size_t(len(header)),
		mp, ml, C.size_t(len(messages))))
}

// BbsVerifyBlindSign verifies a blind signature over signerMsgs + committedMsgs
// using the secretProverBlind kept from BbsBlindCommit.
func BbsVerifyBlindSign(pk, signature, header []byte, signerMsgs, committedMsgs [][]byte, secretProverBlind []byte) bool {
	sm, sl, freeS := cByteSlices(signerMsgs)
	defer freeS()
	cm, cl, freeC := cByteSlices(committedMsgs)
	defer freeC()
	return C.cryptolib_bbs_verify_blind_sign(
		u8(pk), C.size_t(len(pk)), u8(signature), C.size_t(len(signature)),
		u8(header), C.size_t(len(header)),
		sm, sl, C.size_t(len(signerMsgs)), cm, cl, C.size_t(len(committedMsgs)),
		u8(secretProverBlind), C.size_t(len(secretProverBlind))) == 1
}
