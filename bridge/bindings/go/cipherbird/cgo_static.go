//go:build cipherbird_static

package cipherbird

// Fully-static linking, selected with `-tags cipherbird_static`.
//
// This links the merged self-contained archive build/static/libcipherbird_c.a
// (the C ABI plus libsodium, BLAKE3, liboqs, OpenSSL libcrypto, blst and
// libsecp256k1, all baked in). The resulting Go binary has NO dependency on a
// libcipherbird_c shared library at run time — nothing to ship alongside it, no
// rpath, no DYLD_LIBRARY_PATH/LD_LIBRARY_PATH. This is the "just works
// everywhere" option for self-contained deployment.
//
// Build the archive once, then build with the tag:
//
//	scripts/build_static_archive.sh
//	go build -tags cipherbird_static ./...
//
// Only the C++ runtime is still resolved dynamically (-lc++ / -lstdc++), which
// is present on every macOS and Linux system.

/*
#cgo CFLAGS: -I${SRCDIR}/../../../
#cgo darwin LDFLAGS: ${SRCDIR}/../../../../build/static/libcipherbird_c.a -lc++
#cgo linux  LDFLAGS: ${SRCDIR}/../../../../build/static/libcipherbird_c.a -lstdc++ -lm
*/
import "C"
