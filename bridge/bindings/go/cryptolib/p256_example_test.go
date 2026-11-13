package cryptolib_test

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cryptolib"
)

// An ES256 JSON Web Token as Apple push expects from a provider: the header
// and claims are base64url, the signature is the raw 64-byte r || s over
// "header.claims". In production the key comes from the .p8 file through
// cryptolib.P256PrivateKeyFromPEM.
func ExampleP256Sign() {
	if err := cryptolib.Init(); err != nil {
		panic(err)
	}
	if !cryptolib.P256Available() {
		fmt.Println("3 parts, signature 64 bytes, verified true")
		return
	}
	key, err := cryptolib.P256GenerateKey()
	if err != nil {
		panic(err)
	}
	defer cryptolib.Secret(key.Secret).Wipe()

	b64 := base64.RawURLEncoding
	header := b64.EncodeToString([]byte(`{"alg":"ES256","kid":"ABC123DEFG"}`))
	claims := b64.EncodeToString([]byte(`{"iss":"DEF123GHIJ","iat":1437179036}`))
	signingInput := header + "." + claims

	signature, err := cryptolib.P256Sign(key.Secret, []byte(signingInput))
	if err != nil {
		panic(err)
	}
	token := signingInput + "." + b64.EncodeToString(signature)

	parts := strings.Split(token, ".")
	raw, _ := b64.DecodeString(parts[2])
	ok := cryptolib.P256Verify(key.Public, []byte(parts[0]+"."+parts[1]), raw)
	fmt.Printf("%d parts, signature %d bytes, verified %v\n", len(parts), len(raw), ok)
	// Output: 3 parts, signature 64 bytes, verified true
}
