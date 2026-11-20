//go:build cipherbird_pkgconfig && !cipherbird_static && !cipherbird_vendored

package cipherbird

// pkg-config linking configuration, selected with `-tags cipherbird_pkgconfig`.
//
// Use this when libcipherbird_c is installed system-wide and a `cipherbird_c.pc`
// file is on your PKG_CONFIG_PATH. It resolves both the include path and the
// link flags from pkg-config, so no repo-relative paths are involved:
//
//	go build -tags cipherbird_pkgconfig ./...
//
// A ready-to-edit template ships next to this file as `cipherbird_c.pc.in`.
// After installing the header and library, drop a filled-in `cipherbird_c.pc`
// onto your PKG_CONFIG_PATH (e.g. /usr/local/lib/pkgconfig).

/*
#cgo pkg-config: cipherbird_c
*/
import "C"
