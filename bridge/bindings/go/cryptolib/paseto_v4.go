package cryptolib

/*
#cgo noescape cryptolib_paseto_v4_local_encrypt
#cgo nocallback cryptolib_paseto_v4_local_encrypt
#cgo noescape cryptolib_paseto_v4_local_decrypt
#cgo nocallback cryptolib_paseto_v4_local_decrypt
#include "cryptolib_c.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

// PasetoV4LocalKeyBytes is the length of a PASETO v4.local key.
const PasetoV4LocalKeyBytes = C.CRYPTOLIB_PASETO_V4_LOCAL_KEY_BYTES

// PasetoV4MaxInputBytes is the largest message, footer or implicit assertion
// the PASETO v4.local functions accept.
const PasetoV4MaxInputBytes = 1 << 26

const (
	pasetoHeaderLen   = len("v4.local.")
	pasetoOverheadLen = 64
)

// Errors of the PASETO v4.local functions. [PasetoV4LocalDecrypt] returns
// ErrPasetoInvalid for every failure that depends on the token, with no
// further detail, so a caller cannot be used as an oracle.
var (
	ErrPasetoInvalid  = errors.New("cryptolib: invalid PASETO token")
	ErrPasetoKey      = errors.New("cryptolib: PASETO v4.local key must be 32 bytes")
	ErrPasetoArgument = errors.New("cryptolib: PASETO input out of range")
	ErrPasetoInternal = errors.New("cryptolib: PASETO backend failure")
)

func pasetoErr(rc C.int) error {
	switch rc {
	case C.CRYPTOLIB_PASETO_ERR_INVALID:
		return ErrPasetoInvalid
	case C.CRYPTOLIB_PASETO_ERR_ARGUMENT:
		return ErrPasetoArgument
	}
	return ErrPasetoInternal
}

func b64Len(n int) int {
	r := n % 3
	if r == 0 {
		return n / 3 * 4
	}
	return n/3*4 + r + 1
}

// PasetoV4LocalEncryptLen returns the exact length of the token
// [PasetoV4LocalEncrypt] produces for a msgLen-byte message and a
// footerLen-byte footer, or 0 when either is negative or larger than
// [PasetoV4MaxInputBytes]. It is computed in Go, without calling the
// native library, and equals cryptolib_paseto_v4_local_encrypt_len.
func PasetoV4LocalEncryptLen(msgLen, footerLen int) int {
	if msgLen < 0 || footerLen < 0 || msgLen > PasetoV4MaxInputBytes || footerLen > PasetoV4MaxInputBytes {
		return 0
	}
	n := pasetoHeaderLen + b64Len(pasetoOverheadLen+msgLen)
	if footerLen > 0 {
		n += 1 + b64Len(footerLen)
	}
	return n
}

// PasetoV4LocalDecryptCap returns the output capacity
// [PasetoV4LocalDecryptTo] requires for a token of tokenLen bytes, or 0 for
// a length no valid token has. It depends only on the length, is computed
// in Go, and equals cryptolib_paseto_v4_local_decrypt_cap.
func PasetoV4LocalDecryptCap(tokenLen int) int {
	if tokenLen <= pasetoHeaderLen || tokenLen > PasetoV4LocalEncryptLen(PasetoV4MaxInputBytes, PasetoV4MaxInputBytes) {
		return 0
	}
	return (tokenLen - pasetoHeaderLen) * 3 / 4
}

// PasetoV4LocalEncrypt seals message as a PASETO v4.local token under a
// 32-byte key, with a fresh nonce drawn from libsodium's CSPRNG inside the
// native library. footer is appended in clear text and authenticated; an
// empty footer is omitted. implicit is authenticated but not stored. The
// whole construction runs natively in one cgo call that allocates nothing
// and locks no memory; derived keys are wiped before it returns. The only
// Go allocation is the returned token. Each input may be up to
// [PasetoV4MaxInputBytes].
func PasetoV4LocalEncrypt(key, message, footer, implicit []byte) (string, error) {
	if len(key) != PasetoV4LocalKeyBytes {
		return "", ErrPasetoKey
	}
	if len(implicit) > PasetoV4MaxInputBytes {
		return "", ErrPasetoArgument
	}
	n := PasetoV4LocalEncryptLen(len(message), len(footer))
	if n == 0 {
		return "", ErrPasetoArgument
	}
	out := make([]byte, n)
	var outLen C.size_t
	rc := C.cryptolib_paseto_v4_local_encrypt(
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

// PasetoV4LocalDecrypt authenticates and opens a PASETO v4.local token under
// a 32-byte key. expectedFooter must equal the token's footer exactly; empty
// means the token must carry none. implicit must equal the implicit
// assertion used at encryption. The header, a canonical unpadded base64url
// encoding, the footer and the tag (in constant time) are all checked before
// anything is decrypted; any failure returns [ErrPasetoInvalid]. The message
// is returned in a fresh slice that the caller owns; wipe it with
// [Secret.Wipe] when it holds secrets.
func PasetoV4LocalDecrypt(token string, key, expectedFooter, implicit []byte) ([]byte, error) {
	capN, err := pasetoDecryptCap(len(token), key, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	out := make([]byte, capN)
	n, err := PasetoV4LocalDecryptTo(out, token, key, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	return out[:n:n], nil
}

// PasetoV4LocalDecryptTo is [PasetoV4LocalDecrypt] into a buffer the caller
// provides, so a caller can open a token without any Go allocation, for
// example into an array on its stack. out must hold at least
// [PasetoV4LocalDecryptCap](len(token)) bytes, otherwise the call returns
// [ErrPasetoArgument]. On success the message is out[:n] and the rest of
// that capacity is zero; on any failure n is 0 and that whole capacity is
// zero. The checks, their order and the errors are those of
// [PasetoV4LocalDecrypt], in one cgo call.
func PasetoV4LocalDecryptTo(out []byte, token string, key, expectedFooter, implicit []byte) (int, error) {
	capN, err := pasetoDecryptCap(len(token), key, expectedFooter, implicit)
	if err != nil {
		return 0, err
	}
	if len(out) < capN {
		return 0, ErrPasetoArgument
	}
	var outLen C.size_t
	rc := C.cryptolib_paseto_v4_local_decrypt(
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

func pasetoDecryptCap(tokenLen int, key, expectedFooter, implicit []byte) (int, error) {
	if len(key) != PasetoV4LocalKeyBytes {
		return 0, ErrPasetoKey
	}
	if len(expectedFooter) > PasetoV4MaxInputBytes || len(implicit) > PasetoV4MaxInputBytes {
		return 0, ErrPasetoArgument
	}
	capN := PasetoV4LocalDecryptCap(tokenLen)
	if capN == 0 {
		return 0, ErrPasetoInvalid
	}
	return capN, nil
}

func nativePasetoV4LocalEncryptLen(msgLen, footerLen int) int {
	return int(C.cryptolib_paseto_v4_local_encrypt_len(C.size_t(msgLen), C.size_t(footerLen)))
}

func nativePasetoV4LocalDecryptCap(tokenLen int) int {
	return int(C.cryptolib_paseto_v4_local_decrypt_cap(C.size_t(tokenLen)))
}
