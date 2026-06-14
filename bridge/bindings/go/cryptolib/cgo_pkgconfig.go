//go:build cryptolib_pkgconfig && !cryptolib_static

package cryptolib

// pkg-config linking configuration, selected with `-tags cryptolib_pkgconfig`.
//
// Use this when libcryptolib_c is installed system-wide and a `cryptolib_c.pc`
// file is on your PKG_CONFIG_PATH. It resolves both the include path and the
// link flags from pkg-config, so no repo-relative paths are involved:
//
//	go build -tags cryptolib_pkgconfig ./...
//
// A ready-to-edit template ships next to this file as `cryptolib_c.pc.in`.
// After installing the header and library, drop a filled-in `cryptolib_c.pc`
// onto your PKG_CONFIG_PATH (e.g. /usr/local/lib/pkgconfig).

/*
#cgo pkg-config: cryptolib_c
*/
import "C"
