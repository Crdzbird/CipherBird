package cryptolib

/*
#include "cryptolib_c.h"
*/
import "C"

import "errors"

// Blake2bKeyed computes BLAKE2b with an outLen-byte output. The length is a
// BLAKE2b parameter, so the result is not a truncation of the 64-byte
// [Blake2b] digest. outLen must be 1 to 64 and key must be empty (unkeyed)
// or 16 to 64 bytes; anything else returns an error. It suits keyed digests
// and PASERK identifiers; for PASETO tokens use [PasetoV4LocalEncrypt] and
// [PasetoV4LocalDecrypt]. With a key the output is a MAC or derived key
// material: wipe it with [Secret.Wipe] when done.
func Blake2bKeyed(msg, key []byte, outLen int) ([]byte, error) {
	if outLen < 0 {
		return nil, errors.New("cryptolib: Blake2bKeyed requires outLen >= 0")
	}
	return checkBufResult(C.cryptolib_blake2b_keyed(
		u8(msg), C.size_t(len(msg)),
		u8(key), C.size_t(len(key)),
		C.size_t(outLen)))
}
