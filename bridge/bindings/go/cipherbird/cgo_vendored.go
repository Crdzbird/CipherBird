//go:build cipherbird_vendored && !cipherbird_static

package cipherbird

// Vendored, fully self-contained linking — selected with `-tags cipherbird_vendored`.
//
// Links the merged static archive and header that ship INSIDE this module under
// native/ (populated by `make bundle` / scripts/bundle_native.sh). Everything —
// the C ABI plus libsodium, BLAKE3, liboqs, OpenSSL libcrypto (no-sock/no-dso),
// blst and libsecp256k1 — is baked in, so a consumer can `go get` this package
// and build with NO CipherBird source tree, no repo-relative paths, no shared
// library at run time:
//
//	go build -tags cipherbird_vendored ./...
//
// This is the option a published module ships. The archive is host-arch; CI
// vendors the per-platform archives — see PUBLISHING.md.

/*
#cgo CFLAGS: -I${SRCDIR}/native
#cgo darwin LDFLAGS: ${SRCDIR}/native/libcipherbird.a -lc++ -framework Security -framework CoreFoundation
#cgo linux  LDFLAGS: ${SRCDIR}/native/libcipherbird.a -lstdc++ -lm -lpthread -ldl
*/
import "C"
