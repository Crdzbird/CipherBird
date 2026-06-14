//go:build !cryptolib_pkgconfig && !cryptolib_static

package cryptolib

// Default linking configuration.
//
// This is used unless you build with the `cryptolib_pkgconfig` tag. It assumes
// the in-repository layout: the C header lives in `bridge/cryptolib_c.h` and the
// compiled shared library in `build/release/` (relative to the repo root). This
// is what `make` / the monorepo examples use.
//
// Consuming this package from OUTSIDE the repository (via `go get`)?
// The header resolves automatically from the module cache, but the prebuilt
// library does not ship in the module. Point the linker at your own build of
// libcryptolib_c with environment variables — these are appended to the flags
// below, so the last `-L` that actually contains the library wins:
//
//	export CGO_LDFLAGS="-L/opt/cryptolib/lib"
//	export CGO_CFLAGS="-I/opt/cryptolib/include"   # only if the header moved
//	go build ./...
//
// The shared library's install name is `@rpath/libcryptolib_c.<ver>.dylib`, so
// the LDFLAGS below also bake an absolute -rpath to the in-repo build/release
// directory. ${SRCDIR} expands at build time, making the rpath absolute, so dev
// binaries that import this package run with NO DYLD_LIBRARY_PATH/LD_LIBRARY_PATH
// — matching the side-by-side checkout a `replace` directive already assumes.
// (This rpath is a dev convenience baked into the build machine's absolute path;
// it is not meant for distribution. Installed/redistributable builds should use
// `-tags cryptolib_pkgconfig`, see cgo_pkgconfig.go.)
//
// Consuming this package from OUTSIDE the side-by-side layout? The baked rpath
// won't point at your library, so set the loader path at run time:
//
//	export DYLD_LIBRARY_PATH=/opt/cryptolib/lib    # macOS
//	export LD_LIBRARY_PATH=/opt/cryptolib/lib      # Linux

/*
#cgo CFLAGS: -I${SRCDIR}/../../../
#cgo LDFLAGS: -L${SRCDIR}/../../../../build/release -lcryptolib_c -Wl,-rpath,${SRCDIR}/../../../../build/release
*/
import "C"
