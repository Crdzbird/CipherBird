package cryptolib

/*
#include "cryptolib_c.h"
*/
import "C"
import (
	"errors"
)

// Sizes of P-256 keys and signatures: the secret key is the scalar, the
// public key the uncompressed point 0x04 || X || Y, the signature r || s.
const (
	P256SecretKeyBytes = C.CRYPTOLIB_P256_SECRET_KEY_BYTES
	P256PublicKeyBytes = C.CRYPTOLIB_P256_PUBLIC_KEY_BYTES
	P256SignatureBytes = C.CRYPTOLIB_P256_SIGNATURE_BYTES
)

// ErrP256Unavailable is returned when the linked library was built without
// OpenSSL's EC support, as the trimmed mobile and web engines are.
var ErrP256Unavailable = errors.New("cryptolib: P-256 is not available in this build")

// P256Available reports whether the linked library carries P-256.
func P256Available() bool {
	return C.cryptolib_p256_available() != 0
}

// P256DeterministicNonces reports whether [P256Sign] derives its nonce from
// the key and the message (RFC 6979), so the same input always yields the
// same signature and signing draws no randomness. It is true with OpenSSL
// 3.2 and later; otherwise the nonce is libcrypto's hedged random one.
func P256DeterministicNonces() bool {
	return C.cryptolib_p256_available() == 2
}

// P256GenerateKey returns a fresh P-256 key pair: a 32-byte secret key and
// its 65-byte uncompressed public key.
func P256GenerateKey() (KeyPair, error) {
	kp := C.cryptolib_p256_keygen()
	out := KeyPair{Public: goBytes(kp.public_key), Secret: goBytes(kp.secret_key)}
	if len(out.Secret) != P256SecretKeyBytes || len(out.Public) != P256PublicKeyBytes {
		return KeyPair{}, ErrP256Unavailable
	}
	return out, nil
}

// P256PublicKey returns the 65-byte public key of a 32-byte secret key. A
// key of another length or outside 1..n-1 is an error.
func P256PublicKey(secretKey []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_p256_public_key(u8(secretKey), C.size_t(len(secretKey))))
}

// P256Sign signs SHA-256(message) with ECDSA over P-256 and returns the
// 64-byte r || s, the form a JWS ES256 signature carries (RFC 7518) and
// IEEE P1363 defines. The message is hashed inside the call. s is not
// normalised: a signature is malleable and must not be used as an
// identifier.
func P256Sign(secretKey, message []byte) ([]byte, error) {
	return checkBufResult(C.cryptolib_p256_sign(
		u8(secretKey), C.size_t(len(secretKey)),
		u8(message), C.size_t(len(message))))
}

// P256Verify reports whether signature, 64 bytes of r || s with each half in
// 1..n-1, verifies over SHA-256(message) under a 65-byte uncompressed public
// key on the curve. Any other length, range or encoding is false. Both
// halves of the s range are accepted, as JWS requires.
func P256Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) == 0 || len(signature) == 0 {
		return false
	}
	return C.cryptolib_p256_verify(
		u8(publicKey), C.size_t(len(publicKey)),
		u8(message), C.size_t(len(message)),
		u8(signature), C.size_t(len(signature))) == 1
}

// P256PrivateKeyFromPKCS8 imports an unencrypted PKCS#8 private key in DER
// and returns its secret key with the public key derived from it. The parse
// is strict: trailing bytes, another curve or algorithm, an encrypted
// PKCS#8, attributes, a scalar out of range and an embedded public key that
// does not belong to the scalar are all errors. Wipe the secret key with
// [Secret.Wipe] when done.
func P256PrivateKeyFromPKCS8(der []byte) (KeyPair, error) {
	return p256Pair(checkBufResult(C.cryptolib_p256_import_pkcs8_der(u8(der), C.size_t(len(der)))))
}

// P256PrivateKeyFromPEM is [P256PrivateKeyFromPKCS8] on one PEM block
// labelled PRIVATE KEY, the .p8 file Apple issues for push. Only whitespace
// may surround the block; ENCRYPTED PRIVATE KEY and EC PRIVATE KEY blocks
// are refused by name.
func P256PrivateKeyFromPEM(pem []byte) (KeyPair, error) {
	return p256Pair(checkBufResult(C.cryptolib_p256_import_pkcs8_pem(u8(pem), C.size_t(len(pem)))))
}

func p256Pair(both []byte, err error) (KeyPair, error) {
	if err != nil {
		return KeyPair{}, err
	}
	defer Secret(both).Wipe()
	if len(both) != P256SecretKeyBytes+P256PublicKeyBytes {
		return KeyPair{}, ErrP256Unavailable
	}
	return KeyPair{
		Secret: append([]byte(nil), both[:P256SecretKeyBytes]...),
		Public: append([]byte(nil), both[P256SecretKeyBytes:]...),
	}, nil
}
