//go:build !cryptolib_paseto_test_nonce

package cryptolib

import "testing"

func checkPasetoVectorEncrypt(t *testing.T, v pasetoVector, key []byte) {
	t.Log("encrypt half skipped: build with -tags cryptolib_paseto_test_nonce against a library configured with CRYPTOLIB_PASETO_TEST_NONCE=ON")
}
