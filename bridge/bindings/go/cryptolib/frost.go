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
// FROST(Ed25519, SHA-512) — t-of-n threshold Schnorr signatures (RFC 9591)
//
// t of n parties jointly produce ONE ordinary Ed25519 signature: no single
// party can sign, any t can, and the result verifies with standard Ed25519
// against the group public key — verifiers need know nothing of the threshold
// setup. Two rounds: everyone Commit()s, then everyone Sign()s over the message
// plus the full commitment set, and a coordinator Aggregate()s the shares.
//
//	kg, _ := cryptolib.FrostKeygen(5, 3)          // trusted-dealer split, any 3-of-5 sign
//	// each of the 3 signers, round 1:
//	n0, c0, _ := cryptolib.FrostCommit(kg.SecretShares[0], 1)
//	n1, c1, _ := cryptolib.FrostCommit(kg.SecretShares[1], 2)
//	n3, c3, _ := cryptolib.FrostCommit(kg.SecretShares[3], 4)
//	cs := []cryptolib.FrostCommitment{c0, c1, c3}
//	// round 2 (each signer):
//	s0, _ := cryptolib.FrostSign(1, kg.SecretShares[0], kg.GroupPublicKey, n0, msg, cs)
//	s1, _ := cryptolib.FrostSign(2, kg.SecretShares[1], kg.GroupPublicKey, n1, msg, cs)
//	s3, _ := cryptolib.FrostSign(4, kg.SecretShares[3], kg.GroupPublicKey, n3, msg, cs)
//	sig, _ := cryptolib.FrostAggregate(kg.GroupPublicKey, msg, cs, [][]byte{s0, s1, s3})
//	ok := cryptolib.FrostVerify(msg, sig, kg.GroupPublicKey)  // standard Ed25519
// ═══════════════════════════════════════════════════════════════════════════════

// FrostKeyGen is a trusted-dealer split: the group public key plus one secret
// share per participant. Share i (0-based) has FROST identifier i+1.
type FrostKeyGen struct {
	GroupPublicKey []byte   // 32 B
	SecretShares   [][]byte // n × 32 B (secret scalars; keep private)
	PublicShares   [][]byte // n × 32 B (points, for VerifyShare)
}

// FrostCommitment is a participant's public round-1 commitment.
type FrostCommitment struct {
	Identifier uint16
	Hiding     []byte // 32 B point
	Binding    []byte // 32 B point
}

// FrostNonces are a participant's secret round-1 nonces (never share these).
type FrostNonces struct {
	Hiding  []byte // 32 B scalar
	Binding []byte // 32 B scalar
}

// cbufBytes copies a CryptoBuffer into a fresh Go slice WITHOUT freeing it
// (the owning struct's *_free frees the whole allocation once).
func cbufBytes(b C.CryptoBuffer) []byte {
	if b.data == nil || b.len == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(b.data)), int(b.len))...)
}

// frostCommitBufs flattens commitments into the three parallel wire arrays.
func frostCommitBufs(cs []FrostCommitment) (ids []C.uint16_t, hid, bnd []byte) {
	n := len(cs)
	ids = make([]C.uint16_t, n)
	hid = make([]byte, n*32)
	bnd = make([]byte, n*32)
	for i, c := range cs {
		ids[i] = C.uint16_t(c.Identifier)
		copy(hid[i*32:], c.Hiding)
		copy(bnd[i*32:], c.Binding)
	}
	return
}

func frostIDsPtr(ids []C.uint16_t) *C.uint16_t {
	if len(ids) == 0 {
		return nil
	}
	return (*C.uint16_t)(unsafe.Pointer(&ids[0]))
}

// FrostKeygen splits a random group key into n shares, any t of which can sign.
func FrostKeygen(n, t uint16) (*FrostKeyGen, error) {
	kg := C.cryptolib_frost_keygen(C.uint16_t(n), C.uint16_t(t))
	if kg.error != nil {
		msg := C.GoString(kg.error)
		C.cryptolib_frost_keygen_free(&kg)
		return nil, errors.New(msg)
	}
	defer C.cryptolib_frost_keygen_free(&kg)

	count := int(kg.count)
	out := &FrostKeyGen{GroupPublicKey: cbufBytes(kg.group_public_key)}
	secs := unsafe.Slice((*byte)(unsafe.Pointer(kg.secret_shares.data)), int(kg.secret_shares.len))
	pubs := unsafe.Slice((*byte)(unsafe.Pointer(kg.public_shares.data)), int(kg.public_shares.len))
	for i := 0; i < count; i++ {
		out.SecretShares = append(out.SecretShares, append([]byte(nil), secs[i*32:i*32+32]...))
		out.PublicShares = append(out.PublicShares, append([]byte(nil), pubs[i*32:i*32+32]...))
	}
	return out, nil
}

func frostCommitOut(c C.CryptoFrostCommit, identifier uint16) (FrostNonces, FrostCommitment, error) {
	if c.error != nil {
		msg := C.GoString(c.error)
		C.cryptolib_frost_commit_free(&c)
		return FrostNonces{}, FrostCommitment{}, errors.New(msg)
	}
	defer C.cryptolib_frost_commit_free(&c)
	nonces := FrostNonces{Hiding: cbufBytes(c.hiding_nonce), Binding: cbufBytes(c.binding_nonce)}
	commit := FrostCommitment{
		Identifier: identifier,
		Hiding:     cbufBytes(c.hiding_commit),
		Binding:    cbufBytes(c.binding_commit),
	}
	return nonces, commit, nil
}

// FrostCommit generates a fresh random nonce pair + public commitment for a share.
// Keep the returned nonces secret; publish the commitment.
func FrostCommit(shareSecret []byte, identifier uint16) (FrostNonces, FrostCommitment, error) {
	c := C.cryptolib_frost_commit(u8(shareSecret), C.size_t(len(shareSecret)), C.uint16_t(identifier))
	return frostCommitOut(c, identifier)
}

// FrostCommitWithNonces is the deterministic variant (test vectors / caller nonces).
func FrostCommitWithNonces(identifier uint16, hiding, binding []byte) (FrostNonces, FrostCommitment, error) {
	c := C.cryptolib_frost_commit_with_nonces(C.uint16_t(identifier),
		u8(hiding), C.size_t(len(hiding)), u8(binding), C.size_t(len(binding)))
	return frostCommitOut(c, identifier)
}

// FrostSign produces this participant's 32-byte signature share. commitments is
// the full round-1 set from every participating signer (including self).
func FrostSign(identifier uint16, shareSecret, groupPublicKey []byte,
	nonces FrostNonces, msg []byte, commitments []FrostCommitment) ([]byte, error) {
	ids, hid, bnd := frostCommitBufs(commitments)
	return checkBufResult(C.cryptolib_frost_sign(
		C.uint16_t(identifier),
		u8(shareSecret), C.size_t(len(shareSecret)),
		u8(groupPublicKey), C.size_t(len(groupPublicKey)),
		u8(nonces.Hiding), C.size_t(len(nonces.Hiding)),
		u8(nonces.Binding), C.size_t(len(nonces.Binding)),
		u8(msg), C.size_t(len(msg)),
		frostIDsPtr(ids), u8(hid), u8(bnd), C.size_t(len(commitments))))
}

// FrostAggregate combines signature shares into one 64-byte Ed25519 signature.
func FrostAggregate(groupPublicKey, msg []byte, commitments []FrostCommitment,
	sigShares [][]byte) ([]byte, error) {
	ids, hid, bnd := frostCommitBufs(commitments)
	flat := make([]byte, len(sigShares)*32)
	for i, s := range sigShares {
		copy(flat[i*32:], s)
	}
	return checkBufResult(C.cryptolib_frost_aggregate(
		u8(groupPublicKey), C.size_t(len(groupPublicKey)),
		u8(msg), C.size_t(len(msg)),
		frostIDsPtr(ids), u8(hid), u8(bnd), C.size_t(len(commitments)),
		u8(flat)))
}

// FrostVerify verifies an aggregate signature with standard Ed25519.
func FrostVerify(msg, sig, groupPublicKey []byte) bool {
	return C.cryptolib_frost_verify(
		u8(msg), C.size_t(len(msg)),
		u8(sig), C.size_t(len(sig)),
		u8(groupPublicKey), C.size_t(len(groupPublicKey))) == 1
}

// FrostVerifyShare checks a single participant's signature share against its
// public share (coordinator robustness — identify a misbehaving signer).
func FrostVerifyShare(identifier uint16, publicShare, sigShare []byte,
	commitment FrostCommitment, groupPublicKey, msg []byte,
	commitments []FrostCommitment) bool {
	ids, hid, bnd := frostCommitBufs(commitments)
	return C.cryptolib_frost_verify_share(
		C.uint16_t(identifier),
		u8(publicShare), C.size_t(len(publicShare)),
		u8(sigShare), C.size_t(len(sigShare)),
		u8(commitment.Hiding), C.size_t(len(commitment.Hiding)),
		u8(commitment.Binding), C.size_t(len(commitment.Binding)),
		u8(groupPublicKey), C.size_t(len(groupPublicKey)),
		u8(msg), C.size_t(len(msg)),
		frostIDsPtr(ids), u8(hid), u8(bnd), C.size_t(len(commitments))) == 1
}
