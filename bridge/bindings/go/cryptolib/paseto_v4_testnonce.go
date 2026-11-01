//go:build cryptolib_paseto_test_nonce

package cryptolib

/*
#define CRYPTOLIB_PASETO_TEST_NONCE 1
#include "cryptolib_c.h"
*/
import "C"

import "unsafe"

// PasetoV4LocalEncryptWithNonceForTesting is [PasetoV4LocalEncrypt] with a
// caller-chosen 32-byte nonce, for reproducing the official test vectors. It
// exists only under the cryptolib_paseto_test_nonce build tag and links only
// against a library configured with CRYPTOLIB_PASETO_TEST_NONCE=ON, which
// the bank and fips profiles refuse. Never use it outside tests: a repeated
// nonce under one key reuses the keystream.
func PasetoV4LocalEncryptWithNonceForTesting(key, message, footer, implicit, nonce []byte) (string, error) {
	if len(key) != PasetoV4LocalKeyBytes {
		return "", ErrPasetoKey
	}
	n := C.cryptolib_paseto_v4_local_encrypt_len(C.size_t(len(message)), C.size_t(len(footer)))
	if n == 0 {
		return "", ErrPasetoArgument
	}
	out := make([]byte, int(n))
	var outLen C.size_t
	rc := C.cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
		u8(out), n, &outLen,
		u8(key), C.size_t(len(key)),
		u8(message), C.size_t(len(message)),
		u8(footer), C.size_t(len(footer)),
		u8(implicit), C.size_t(len(implicit)),
		u8(nonce), C.size_t(len(nonce)))
	if rc != C.CRYPTOLIB_PASETO_OK {
		return "", pasetoErr(rc)
	}
	return unsafe.String(&out[0], int(outLen)), nil
}
