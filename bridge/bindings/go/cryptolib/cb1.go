package cryptolib

/*
#cgo noescape cryptolib_cb1_local_encrypt
#cgo nocallback cryptolib_cb1_local_encrypt
#cgo noescape cryptolib_cb1_local_decrypt
#cgo nocallback cryptolib_cb1_local_decrypt
#cgo noescape cryptolib_cb1_public_sign
#cgo nocallback cryptolib_cb1_public_sign
#cgo noescape cryptolib_cb1_public_verify
#cgo nocallback cryptolib_cb1_public_verify
#cgo noescape cryptolib_blake2b_keyed_into
#cgo nocallback cryptolib_blake2b_keyed_into
#include "cryptolib_c.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

// Sizes of the cb1 token keys: the local key, and the Ed25519 + ML-DSA-65
// hybrid pair of [HybridSigKeygen] for public tokens.
const (
	Cb1LocalKeyBytes  = C.CRYPTOLIB_CB1_LOCAL_KEY_BYTES
	Cb1PublicKeyBytes = C.CRYPTOLIB_CB1_PUBLIC_KEY_BYTES
	Cb1SecretKeyBytes = C.CRYPTOLIB_CB1_SECRET_KEY_BYTES
	Cb1SignatureBytes = C.CRYPTOLIB_CB1_SIGNATURE_BYTES
	// Cb1MaxInputBytes is the largest message, footer or implicit assertion
	// the cb1 functions accept.
	Cb1MaxInputBytes = 1 << 26
)

const (
	cb1LocalHeaderLen  = len("cb1.local.")
	cb1PublicHeaderLen = len("cb1.public.")
	cb1LocalOverhead   = 64
)

// ErrPasetoUnavailable is returned by the cb1 functions when the linked
// library is the bank profile, which ships only standards-track formats.
var ErrPasetoUnavailable = errors.New("cryptolib: cb1 tokens are not available in this build profile")

// Cb1LocalEncryptLen returns the exact length of the token
// [Cb1LocalEncrypt] produces for a msgLen-byte message and a footerLen-byte
// footer, or 0 when either is negative or larger than [Cb1MaxInputBytes].
// Computed in Go; equals cryptolib_cb1_local_encrypt_len.
func Cb1LocalEncryptLen(msgLen, footerLen int) int {
	if msgLen < 0 || footerLen < 0 || msgLen > Cb1MaxInputBytes || footerLen > Cb1MaxInputBytes {
		return 0
	}
	n := cb1LocalHeaderLen + b64Len(cb1LocalOverhead+msgLen)
	if footerLen > 0 {
		n += 1 + b64Len(footerLen)
	}
	return n
}

// Cb1LocalDecryptCap returns the output capacity [Cb1LocalDecryptTo]
// requires for a token of tokenLen bytes, or 0 for a length no valid token
// has. Computed in Go; equals cryptolib_cb1_local_decrypt_cap.
func Cb1LocalDecryptCap(tokenLen int) int {
	if tokenLen <= cb1LocalHeaderLen || tokenLen > Cb1LocalEncryptLen(Cb1MaxInputBytes, Cb1MaxInputBytes) {
		return 0
	}
	return (tokenLen - cb1LocalHeaderLen) * 3 / 4
}

// Cb1PublicSignLen returns the exact length of the token [Cb1PublicSign]
// produces for a msgLen-byte message and a footerLen-byte footer, or 0 when
// either is out of range. Computed in Go; equals cryptolib_cb1_public_sign_len.
func Cb1PublicSignLen(msgLen, footerLen int) int {
	if msgLen < 0 || footerLen < 0 || msgLen > Cb1MaxInputBytes || footerLen > Cb1MaxInputBytes {
		return 0
	}
	n := cb1PublicHeaderLen + b64Len(msgLen+Cb1SignatureBytes)
	if footerLen > 0 {
		n += 1 + b64Len(footerLen)
	}
	return n
}

// Cb1PublicVerifyCap returns the output capacity [Cb1PublicVerifyTo]
// requires for a token of tokenLen bytes, or 0 for a length no valid token
// has. Computed in Go; equals cryptolib_cb1_public_verify_cap.
func Cb1PublicVerifyCap(tokenLen int) int {
	if tokenLen <= cb1PublicHeaderLen || tokenLen > Cb1PublicSignLen(Cb1MaxInputBytes, Cb1MaxInputBytes) {
		return 0
	}
	return (tokenLen - cb1PublicHeaderLen) * 3 / 4
}

// Cb1LocalEncrypt seals message as a cb1.local token under a 32-byte key:
// PASETO v4.local with BLAKE3 in place of BLAKE2b, a fresh nonce from the
// native CSPRNG, the footer appended in clear and authenticated, implicit
// authenticated but not stored. One cgo call that allocates nothing; the
// only Go allocation is the returned token.
func Cb1LocalEncrypt(key, message, footer, implicit []byte) (string, error) {
	if len(key) != Cb1LocalKeyBytes {
		return "", ErrPasetoKey
	}
	if len(implicit) > Cb1MaxInputBytes {
		return "", ErrPasetoArgument
	}
	n := Cb1LocalEncryptLen(len(message), len(footer))
	if n == 0 {
		return "", ErrPasetoArgument
	}
	out := make([]byte, n)
	var outLen C.size_t
	rc := C.cryptolib_cb1_local_encrypt(
		u8(out), C.size_t(n), &outLen,
		u8(key), C.size_t(len(key)),
		u8(message), C.size_t(len(message)),
		u8(footer), C.size_t(len(footer)),
		u8(implicit), C.size_t(len(implicit)))
	if rc != C.CRYPTOLIB_PASETO_OK || int(outLen) != n {
		return "", pasetoErr(rc)
	}
	return unsafe.String(&out[0], n), nil
}

// Cb1LocalDecrypt authenticates and opens a cb1.local token under a 32-byte
// key; expectedFooter and implicit must match exactly. Every failure that
// depends on the token is [ErrPasetoInvalid]. The message is returned in a
// fresh slice; wipe it with [Secret.Wipe] when it holds secrets.
func Cb1LocalDecrypt(token string, key, expectedFooter, implicit []byte) ([]byte, error) {
	capN, err := cb1Cap(Cb1LocalDecryptCap(len(token)), len(key), Cb1LocalKeyBytes, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	out := make([]byte, capN)
	n, err := Cb1LocalDecryptTo(out, token, key, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	return out[:n:n], nil
}

// Cb1LocalDecryptTo is [Cb1LocalDecrypt] into a buffer the caller provides,
// of at least [Cb1LocalDecryptCap](len(token)) bytes, so a token can be
// opened without any Go allocation. On success the message is out[:n] and
// the rest of that capacity is zero; on failure n is 0 and the capacity is
// zero.
func Cb1LocalDecryptTo(out []byte, token string, key, expectedFooter, implicit []byte) (int, error) {
	capN, err := cb1Cap(Cb1LocalDecryptCap(len(token)), len(key), Cb1LocalKeyBytes, expectedFooter, implicit)
	if err != nil {
		return 0, err
	}
	if len(out) < capN {
		return 0, ErrPasetoArgument
	}
	var outLen C.size_t
	rc := C.cryptolib_cb1_local_decrypt(
		u8(out), C.size_t(capN), &outLen,
		(*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token))), C.size_t(len(token)),
		u8(key), C.size_t(len(key)),
		u8(expectedFooter), C.size_t(len(expectedFooter)),
		u8(implicit), C.size_t(len(implicit)))
	if rc != C.CRYPTOLIB_PASETO_OK {
		return 0, pasetoErr(rc)
	}
	return int(outLen), nil
}

// Cb1PublicSign signs message as a cb1.public token with a 4096-byte hybrid
// secret key from [HybridSigKeygen]: PASETO v4.public with the Ed25519 +
// ML-DSA-65 signature in place of Ed25519, over PAE("cb1.public.", m,
// footer, implicit). The token carries the message in clear.
func Cb1PublicSign(secretKey, message, footer, implicit []byte) (string, error) {
	if len(secretKey) != Cb1SecretKeyBytes {
		return "", ErrPasetoKey
	}
	if len(implicit) > Cb1MaxInputBytes {
		return "", ErrPasetoArgument
	}
	n := Cb1PublicSignLen(len(message), len(footer))
	if n == 0 {
		return "", ErrPasetoArgument
	}
	out := make([]byte, n)
	var outLen C.size_t
	rc := C.cryptolib_cb1_public_sign(
		u8(out), C.size_t(n), &outLen,
		u8(secretKey), C.size_t(len(secretKey)),
		u8(message), C.size_t(len(message)),
		u8(footer), C.size_t(len(footer)),
		u8(implicit), C.size_t(len(implicit)))
	if rc != C.CRYPTOLIB_PASETO_OK || int(outLen) != n {
		return "", pasetoErr(rc)
	}
	return unsafe.String(&out[0], n), nil
}

// Cb1PublicVerify checks a cb1.public token against a 1984-byte hybrid
// public key and returns its message only when both signature halves
// verify over the expected footer and implicit assertion. Every failure
// that depends on the token is [ErrPasetoInvalid].
func Cb1PublicVerify(token string, publicKey, expectedFooter, implicit []byte) ([]byte, error) {
	capN, err := cb1Cap(Cb1PublicVerifyCap(len(token)), len(publicKey), Cb1PublicKeyBytes, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	out := make([]byte, capN)
	n, err := Cb1PublicVerifyTo(out, token, publicKey, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	return out[:n:n], nil
}

// Cb1PublicVerifyTo is [Cb1PublicVerify] into a buffer the caller provides,
// of at least [Cb1PublicVerifyCap](len(token)) bytes.
func Cb1PublicVerifyTo(out []byte, token string, publicKey, expectedFooter, implicit []byte) (int, error) {
	capN, err := cb1Cap(Cb1PublicVerifyCap(len(token)), len(publicKey), Cb1PublicKeyBytes, expectedFooter, implicit)
	if err != nil {
		return 0, err
	}
	if len(out) < capN {
		return 0, ErrPasetoArgument
	}
	var outLen C.size_t
	rc := C.cryptolib_cb1_public_verify(
		u8(out), C.size_t(capN), &outLen,
		(*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token))), C.size_t(len(token)),
		u8(publicKey), C.size_t(len(publicKey)),
		u8(expectedFooter), C.size_t(len(expectedFooter)),
		u8(implicit), C.size_t(len(implicit)))
	if rc != C.CRYPTOLIB_PASETO_OK {
		return 0, pasetoErr(rc)
	}
	return int(outLen), nil
}

// Blake2bKeyedInto is [Blake2bKeyed] written straight into out, whose
// length (1 to 64) selects the digest length, so a short keyed digest costs
// one cgo call and no allocation. key must be empty (unkeyed) or 16 to 64
// bytes. On any error out is zeroed.
func Blake2bKeyedInto(out, msg, key []byte) error {
	if len(out) == 0 {
		return ErrPasetoArgument
	}
	rc := C.cryptolib_blake2b_keyed_into(
		u8(out), C.size_t(len(out)),
		u8(msg), C.size_t(len(msg)),
		u8(key), C.size_t(len(key)))
	if rc != C.CRYPTOLIB_PASETO_OK {
		return pasetoErr(rc)
	}
	return nil
}

func cb1Cap(capN, keyLen, wantKey int, expectedFooter, implicit []byte) (int, error) {
	if keyLen != wantKey {
		return 0, ErrPasetoKey
	}
	if len(expectedFooter) > Cb1MaxInputBytes || len(implicit) > Cb1MaxInputBytes {
		return 0, ErrPasetoArgument
	}
	if capN == 0 {
		return 0, ErrPasetoInvalid
	}
	return capN, nil
}

func nativeCb1LocalEncryptLen(msgLen, footerLen int) int {
	return int(C.cryptolib_cb1_local_encrypt_len(C.size_t(msgLen), C.size_t(footerLen)))
}

func nativeCb1LocalDecryptCap(tokenLen int) int {
	return int(C.cryptolib_cb1_local_decrypt_cap(C.size_t(tokenLen)))
}

func nativeCb1PublicSignLen(msgLen, footerLen int) int {
	return int(C.cryptolib_cb1_public_sign_len(C.size_t(msgLen), C.size_t(footerLen)))
}

func nativeCb1PublicVerifyCap(tokenLen int) int {
	return int(C.cryptolib_cb1_public_verify_cap(C.size_t(tokenLen)))
}
