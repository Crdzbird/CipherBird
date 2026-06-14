// Package cryptolib provides idiomatic Go bindings for CryptoLib, a
// header-only C++20 cryptography library exposed through a stable C ABI
// (libcryptolib_c).
//
// It wraps modern, vetted primitives — authenticated encryption, public-key
// signatures and key exchange, post-quantum KEMs and signatures, BLS
// aggregation, password hashing, a layered "vault" pipeline, a revocable
// key-slot keyring, media-derived entropy, and Ethereum/Bitcoin interop
// primitives (Keccak-256, RIPEMD-160, secp256k1 ECDSA) — behind a small,
// allocation-safe Go surface.
//
// # Requirements
//
// This package uses cgo and links against the native shared library
// libcryptolib_c (which itself bundles libsodium, liboqs, blst, OpenSSL
// libcrypto and libsecp256k1). You must build that library once and make it
// discoverable at both link time and run time. CGO_ENABLED=1 is required (it is
// the default unless cross-compiling).
//
// # Building and linking
//
// In the CryptoLib repository the default build "just works": the header is
// found at bridge/cryptolib_c.h and the library at build/release. Build it with:
//
//	cmake -B build/release -DCMAKE_BUILD_TYPE=Release
//	cmake --build build/release --target cryptolib_c
//
// Then set the loader path at run time:
//
//	export DYLD_LIBRARY_PATH=$PWD/build/release   # macOS
//	export LD_LIBRARY_PATH=$PWD/build/release     # Linux
//
// When importing this package from another module via `go get`, the prebuilt
// library is not part of the Go module. Provide your own build of
// libcryptolib_c and point the toolchain at it with environment variables:
//
//	export CGO_LDFLAGS="-L/opt/cryptolib/lib"
//	export CGO_CFLAGS="-I/opt/cryptolib/include"   # if the header is elsewhere
//	export DYLD_LIBRARY_PATH=/opt/cryptolib/lib    # macOS, run time
//	export LD_LIBRARY_PATH=/opt/cryptolib/lib      # Linux, run time
//
// Or, if the library is installed system-wide with a pkg-config file (a
// template ships as cryptolib_c.pc.in), build with the pkg-config tag:
//
//	go build -tags cryptolib_pkgconfig ./...
//
// # Fully static linking (no runtime library)
//
// For the most convenient deployment, link everything — the C ABI and all its
// dependencies — into the binary so there is NO shared library to ship or locate
// at run time:
//
//	scripts/build_static_archive.sh        # builds build/static/libcryptolib_c.a
//	go build -tags cryptolib_static ./...   # or: make go-static
//
// The resulting binary depends only on system libraries (the C++ runtime stays
// dynamic). Building with CGO_ENABLED=0 is unsupported and fails fast with a
// descriptive message rather than a confusing wall of linker errors.
//
// # Quick start
//
//	package main
//
//	import (
//	    "fmt"
//
//	    "github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
//	)
//
//	func main() {
//	    if err := cryptolib.Init(); err != nil { // once, at startup
//	        panic(err)
//	    }
//	    key, _ := cryptolib.SymKeygen()
//	    ct, _ := cryptolib.XChaCha20Encrypt([]byte("hello"), key, nil)
//	    pt, _ := cryptolib.XChaCha20Decrypt(ct, key, nil)
//	    fmt.Printf("%s\n", pt) // hello
//	}
//
// # Initialisation
//
// Call [Init] once before any other operation. It initialises the underlying
// libsodium runtime and is safe to call from multiple goroutines, but it must
// complete before the first crypto call. [Version] reports the native library
// version.
//
// # Error handling
//
// Fallible operations return ([]byte, error) (or a typed result and error). A
// nil error means success. Errors carry the message produced by the C layer;
// the binding never panics on malformed or empty input — bad input yields an
// error, not a crash. Verification helpers (for example [Ed25519Verify],
// [Secp256k1Verify], [HmacSHA256Verify]) return a bool and perform the
// comparison in constant time inside the native library.
//
// # Memory and ownership
//
// All secret-bearing and output buffers are allocated by the C layer and copied
// into garbage-collected Go slices before being returned; the binding frees the
// native allocation immediately, on every path including errors. Callers own the
// returned Go slices and never free anything manually. Secrets inside the native
// library are zeroised on free.
//
// # Handles and lifecycle
//
// Stateful objects — [StreamEncryptor], [StreamDecryptor], [Vault], [Keyring]
// and [Entropy] — wrap an opaque native handle. Each has a Close method that
// releases the handle. Close is idempotent and cancels the object's finalizer,
// so an explicit Close followed by garbage collection cannot double-free. A
// finalizer is also registered as a safety net, but relying on it is
// discouraged: call Close explicitly (typically with defer) to release native
// memory deterministically.
//
//	v, err := cryptolib.NewVault(masterKey, cryptolib.KdfSensitive)
//	if err != nil { /* ... */ }
//	defer v.Close()
//
// Every method that uses a handle keeps the receiver alive across the C call
// (via runtime.KeepAlive), so the finalizer can never free a handle that an
// in-flight call is still using.
//
// # Concurrency
//
// The stateless top-level functions (hashes, signatures, KEMs, AEAD one-shots,
// secp256k1, BLS, …) are safe to call concurrently from many goroutines. The
// handle types hold mutable native state and are NOT safe for concurrent use of
// the SAME handle without external synchronisation; use one handle per goroutine
// or guard it with a mutex. Concurrent Close from multiple goroutines on one
// handle is likewise the caller's responsibility to serialise.
//
// # Feature map
//
// The surface is grouped by domain:
//
//   - Hashing: [Blake2b], [Blake3], [Blake3Keyed], [Blake3DeriveKey], [SHA256],
//     [SHA512], [HmacSHA256], [HmacSHA512], [HkdfExtract], [HkdfExpand],
//     [HkdfDerive], [Argon2idHashStr], [Argon2idDerive].
//   - Symmetric AEAD: [XChaCha20Encrypt]/[XChaCha20Decrypt],
//     [AES256GCMEncrypt]/[AES256GCMDecrypt], [CommittingEncrypt]/[CommittingDecrypt],
//     and the [StreamEncryptor]/[StreamDecryptor] streaming AEAD.
//   - Asymmetric: [Ed25519Keygen]/[Ed25519Sign]/[Ed25519Verify],
//     [X25519Keygen]/[X25519SharedSecret], [BoxKeygen]/[BoxEncrypt]/[BoxDecrypt],
//     sealed boxes.
//   - Post-quantum: ML-KEM, ML-DSA, SLH-DSA, plus the [HybridKemKeygen]
//     (X25519+ML-KEM-768) and [HybridSigKeygen] (Ed25519+ML-DSA-65) constructions.
//   - BLS12-381: [BlsKeygen], [BlsSign], [BlsVerify], [BlsAggregate],
//     [BlsAggregateVerify], [BlsKeygenFromIkm].
//   - Vault & Keyring: [Vault] (4-layer KDF→integrity→AEAD→signature) and
//     [Keyring] (revocable device/passphrase unlock slots).
//   - Media entropy: [EntropyFromFiles], [EntropyFromFilesDeterministic] and the
//     [Entropy] handle's key-derivation methods.
//   - EVM/Bitcoin interop: [Keccak256], [Ripemd160], [Secp256k1Keygen],
//     [Secp256k1Sign], [Secp256k1Verify], [Secp256k1Recover], [Secp256k1Pubkey].
//
// # Testing
//
// The package ships a race-tested robustness suite. Run it against your build of
// the library:
//
//	DYLD_LIBRARY_PATH=../../../build/release go test -race ./cryptolib   # macOS
//	LD_LIBRARY_PATH=../../../build/release  go test -race ./cryptolib    # Linux
//
// CryptoLib is released under the MIT License.
package cryptolib
