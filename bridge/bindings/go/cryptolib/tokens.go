package cryptolib

/*
#cgo noescape cryptolib_token_formats
#cgo nocallback cryptolib_token_formats
#cgo noescape cryptolib_token_issue_len
#cgo nocallback cryptolib_token_issue_len
#cgo noescape cryptolib_token_accept_cap
#cgo nocallback cryptolib_token_accept_cap
#cgo noescape cryptolib_token_keygen
#cgo nocallback cryptolib_token_keygen
#cgo noescape cryptolib_token_issue
#cgo nocallback cryptolib_token_issue
#cgo noescape cryptolib_token_accept
#cgo nocallback cryptolib_token_accept
#cgo noescape cryptolib_token_peek_format
#cgo nocallback cryptolib_token_peek_format
#cgo noescape cryptolib_token_peek_footer
#cgo nocallback cryptolib_token_peek_footer
#include "cryptolib_c.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

// ErrTokenFormat is returned when a format name matches no token format the
// linked engine knows; [TokenFormats] lists them.
var ErrTokenFormat = errors.New("cryptolib: unknown token format")

// TokenFormat is one entry of the engine's token table (docs/TOKEN_API.md):
// a format is named by its token header without the trailing dot, such as
// "v4.local", "cb1.local" or "cb1.public". A local format encrypts under a
// shared key of KeyBytes; a public format signs with the SecretKeyBytes half
// of a pair and verifies with the PublicKeyBytes half. Available is false
// where the format is not in the linked profile; its calls then return
// [ErrPasetoUnavailable].
type TokenFormat struct {
	Format         string `json:"format"`
	Purpose        string `json:"purpose"`
	Standard       string `json:"standard"`
	KeyBytes       int    `json:"key_bytes"`
	PublicKeyBytes int    `json:"public_key_bytes"`
	SecretKeyBytes int    `json:"secret_key_bytes"`
	SignatureBytes int    `json:"signature_bytes"`
	MaxInputBytes  int    `json:"max_input_bytes"`
	Available      bool   `json:"available"`
}

// TokenKeys is what [TokenKeygen] returns: the shared key of a local format
// in Secret with Public nil, or both halves of a public format's pair.
type TokenKeys struct {
	Secret []byte
	Public []byte
}

// TokenFormats returns every token format the engine knows, available or
// not, as the engine describes them.
func TokenFormats() ([]TokenFormat, error) {
	n := C.cryptolib_token_formats(nil, 0)
	if n == 0 {
		return nil, ErrPasetoInternal
	}
	buf := make([]byte, int(n))
	if C.cryptolib_token_formats((*C.char)(unsafe.Pointer(&buf[0])), n) != n {
		return nil, ErrPasetoInternal
	}
	var out []TokenFormat
	if err := json.Unmarshal(buf, &out); err != nil {
		return nil, ErrPasetoInternal
	}
	return out, nil
}

func cFormat(format string) *C.char {
	return C.CString(format)
}

// TokenIssueLen returns the exact length of the token [TokenIssue] produces
// in format for a payloadLen-byte payload and a footerLen-byte footer, or 0
// for an unknown or unavailable format or a length out of range.
func TokenIssueLen(format string, payloadLen, footerLen int) int {
	if payloadLen < 0 || footerLen < 0 {
		return 0
	}
	cf := cFormat(format)
	defer C.free(unsafe.Pointer(cf))
	return int(C.cryptolib_token_issue_len(cf, C.size_t(payloadLen), C.size_t(footerLen)))
}

// TokenAcceptCap returns the output capacity [TokenAcceptTo] requires for a
// token of tokenLen bytes in format, or 0 for an unknown or unavailable
// format or a length no valid token has.
func TokenAcceptCap(format string, tokenLen int) int {
	if tokenLen < 0 {
		return 0
	}
	cf := cFormat(format)
	defer C.free(unsafe.Pointer(cf))
	return int(C.cryptolib_token_accept_cap(cf, C.size_t(tokenLen)))
}

// TokenKeygen returns a fresh key for format: the shared key of a local
// format from the native CSPRNG, or the pair of a public format.
func TokenKeygen(format string) (TokenKeys, error) {
	cf := cFormat(format)
	defer C.free(unsafe.Pointer(cf))
	secret := make([]byte, 4096)
	public := make([]byte, 1984)
	var secretLen, publicLen C.size_t
	rc := C.cryptolib_token_keygen(cf,
		u8(secret), C.size_t(len(secret)), &secretLen,
		u8(public), C.size_t(len(public)), &publicLen)
	if rc != C.CRYPTOLIB_TOKEN_OK {
		return TokenKeys{}, pasetoErr(rc)
	}
	k := TokenKeys{Secret: secret[:int(secretLen):int(secretLen)]}
	if publicLen != 0 {
		k.Public = public[:int(publicLen):int(publicLen)]
	}
	return k, nil
}

// TokenIssue issues a token in format: encrypts payload under key for a
// local format, or signs it with key, the secret half of a pair, for a
// public format. The footer travels in clear and is authenticated; the
// implicit assertion is authenticated but never stored. One cgo call that
// allocates nothing; the only Go allocation is the returned token.
func TokenIssue(format string, key, payload, footer, implicit []byte) (string, error) {
	if len(payload) > Cb1MaxInputBytes || len(footer) > Cb1MaxInputBytes || len(implicit) > Cb1MaxInputBytes {
		return "", ErrPasetoArgument
	}
	cf := cFormat(format)
	defer C.free(unsafe.Pointer(cf))
	n := int(C.cryptolib_token_issue_len(cf, C.size_t(len(payload)), C.size_t(len(footer))))
	if n == 0 {
		out := make([]byte, 1)
		var outLen C.size_t
		rc := C.cryptolib_token_issue(cf, u8(out), 1, &outLen, u8(key), C.size_t(len(key)),
			u8(payload), C.size_t(len(payload)), u8(footer), C.size_t(len(footer)), u8(implicit), C.size_t(len(implicit)))
		if rc == C.CRYPTOLIB_TOKEN_OK {
			return "", ErrPasetoInternal
		}
		return "", pasetoErr(rc)
	}
	out := make([]byte, n)
	var outLen C.size_t
	rc := C.cryptolib_token_issue(cf,
		u8(out), C.size_t(n), &outLen,
		u8(key), C.size_t(len(key)),
		u8(payload), C.size_t(len(payload)),
		u8(footer), C.size_t(len(footer)),
		u8(implicit), C.size_t(len(implicit)))
	if rc != C.CRYPTOLIB_TOKEN_OK || int(outLen) != n {
		return "", pasetoErr(rc)
	}
	return unsafe.String(&out[0], n), nil
}

// TokenAccept accepts a token of format: decrypts it under key for a local
// format, or verifies it with key, the public half of a pair, for a public
// format, and returns the payload. The token's header must be format; any
// other header is [ErrPasetoInvalid], decided before the key is used, so the
// header inside a token never chooses the algorithm. expectedFooter and
// implicit must match exactly, and every failure that depends on the token
// is [ErrPasetoInvalid]. The payload is returned in a fresh slice; wipe it
// with [Secret.Wipe] when it holds secrets.
func TokenAccept(format, token string, key, expectedFooter, implicit []byte) ([]byte, error) {
	capN := TokenAcceptCap(format, len(token))
	if capN == 0 {
		cf := cFormat(format)
		defer C.free(unsafe.Pointer(cf))
		var outLen C.size_t
		rc := C.cryptolib_token_accept(cf, nil, 0, &outLen,
			(*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token))), C.size_t(len(token)),
			u8(key), C.size_t(len(key)), u8(expectedFooter), C.size_t(len(expectedFooter)),
			u8(implicit), C.size_t(len(implicit)))
		if rc == C.CRYPTOLIB_TOKEN_OK {
			return nil, ErrPasetoInvalid
		}
		return nil, pasetoErr(rc)
	}
	out := make([]byte, capN)
	n, err := TokenAcceptTo(out, format, token, key, expectedFooter, implicit)
	if err != nil {
		return nil, err
	}
	return out[:n:n], nil
}

// TokenAcceptTo is [TokenAccept] into a buffer the caller provides, of at
// least [TokenAcceptCap](format, len(token)) bytes, so a token can be
// opened without any Go allocation. On success the payload is out[:n] and
// the rest of that capacity is zero; on failure n is 0 and the capacity is
// zero.
func TokenAcceptTo(out []byte, format, token string, key, expectedFooter, implicit []byte) (int, error) {
	if len(expectedFooter) > Cb1MaxInputBytes || len(implicit) > Cb1MaxInputBytes {
		return 0, ErrPasetoArgument
	}
	cf := cFormat(format)
	defer C.free(unsafe.Pointer(cf))
	capN := int(C.cryptolib_token_accept_cap(cf, C.size_t(len(token))))
	if capN == 0 || len(out) < capN {
		if capN != 0 {
			return 0, ErrPasetoArgument
		}
		var outLen C.size_t
		rc := C.cryptolib_token_accept(cf, nil, 0, &outLen,
			(*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token))), C.size_t(len(token)),
			u8(key), C.size_t(len(key)), u8(expectedFooter), C.size_t(len(expectedFooter)),
			u8(implicit), C.size_t(len(implicit)))
		if rc == C.CRYPTOLIB_TOKEN_OK {
			return 0, ErrPasetoInvalid
		}
		return 0, pasetoErr(rc)
	}
	var outLen C.size_t
	rc := C.cryptolib_token_accept(cf,
		u8(out), C.size_t(capN), &outLen,
		(*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token))), C.size_t(len(token)),
		u8(key), C.size_t(len(key)),
		u8(expectedFooter), C.size_t(len(expectedFooter)),
		u8(implicit), C.size_t(len(implicit)))
	if rc != C.CRYPTOLIB_TOKEN_OK {
		return 0, pasetoErr(rc)
	}
	return int(outLen), nil
}

// TokenPeekFormat returns the header of token as a format name, UNVERIFIED:
// "cb1.local" for a token that starts with "cb1.local.", or "" when the
// text has no header of the known shape. The name need not be a format this
// engine knows, and nothing it says is trusted until [TokenAccept] succeeds
// with that format.
func TokenPeekFormat(token string) string {
	if len(token) == 0 {
		return ""
	}
	t := (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token)))
	n := C.cryptolib_token_peek_format(t, C.size_t(len(token)), nil, 0)
	if n == 0 {
		return ""
	}
	out := make([]byte, int(n))
	if C.cryptolib_token_peek_format(t, C.size_t(len(token)), (*C.char)(unsafe.Pointer(&out[0])), n) != n {
		return ""
	}
	return string(out)
}

// TokenPeekFooter returns the decoded footer of token, UNVERIFIED, for
// choosing a key by its id: nil for a token without a footer,
// [ErrPasetoInvalid] when the text has no header of the known shape or the
// footer is not base64url. The footer [TokenAccept] compares is the
// caller's expectedFooter, never the one read here.
func TokenPeekFooter(token string) ([]byte, error) {
	if len(token) == 0 {
		return nil, ErrPasetoInvalid
	}
	t := (*C.uint8_t)(unsafe.Pointer(unsafe.StringData(token)))
	out := make([]byte, len(token))
	var outLen C.size_t
	rc := C.cryptolib_token_peek_footer(t, C.size_t(len(token)), u8(out), C.size_t(len(out)), &outLen)
	if rc != C.CRYPTOLIB_TOKEN_OK {
		return nil, pasetoErr(rc)
	}
	if outLen == 0 {
		return nil, nil
	}
	return out[:int(outLen):int(outLen)], nil
}
