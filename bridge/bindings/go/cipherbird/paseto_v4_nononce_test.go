//go:build !cipherbird_paseto_test_nonce

package cipherbird

import "testing"

func checkPasetoVectorEncrypt(t *testing.T, v pasetoVector, key []byte) {
	t.Log("encrypt half skipped: build with -tags cipherbird_paseto_test_nonce against a library configured with CIPHERBIRD_PASETO_TEST_NONCE=ON")
}
