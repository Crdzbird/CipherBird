# CryptoLib for Go

Idiomatic Go bindings for **CryptoLib** — a header-only C++20 cryptography
library exposed through a stable C ABI (`libcryptolib_c`). One import gives you
authenticated encryption, signatures, key exchange, **post-quantum** KEMs and
signatures, **BLS** aggregation, password hashing, a layered vault pipeline, a
revocable keyring, media-derived entropy, and **EVM/Bitcoin** primitives
(Keccak-256, RIPEMD-160, secp256k1 ECDSA).

```go
import "github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
```

> Uses **cgo**. You need `CGO_ENABLED=1` (the default) and a built copy of the
> native library `libcryptolib_c` at link and run time.

---

## Install

```sh
go get github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib
```

## Prerequisites — build the native library

The Go package links against `libcryptolib_c`, which bundles libsodium, liboqs,
blst, OpenSSL libcrypto and libsecp256k1. Build it once from the CryptoLib repo:

```sh
cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target cryptolib_c
```

This produces `build/release/libcryptolib_c.{dylib,so}`.

## Linking

The package picks one of two configurations.

### 1. Default — in-repo paths (no tags)

Inside the CryptoLib repository it works out of the box: the header is found at
`bridge/cryptolib_c.h` and the library at `build/release/`. Just set the loader
path at run time:

```sh
export DYLD_LIBRARY_PATH=$PWD/build/release   # macOS
export LD_LIBRARY_PATH=$PWD/build/release     # Linux
go run ./bridge/bindings/go/example
```

### 2. External module — point cgo at your build

When you `go get` this package into another project, the prebuilt library is not
part of the Go module. Tell the toolchain where your `libcryptolib_c` lives:

```sh
export CGO_LDFLAGS="-L/opt/cryptolib/lib"
export CGO_CFLAGS="-I/opt/cryptolib/include"   # only if the header moved
export DYLD_LIBRARY_PATH=/opt/cryptolib/lib    # macOS, run time
export LD_LIBRARY_PATH=/opt/cryptolib/lib      # Linux, run time
go build ./...
```

### 3. pkg-config (system install)

If the library is installed system-wide with a `cryptolib_c.pc` on your
`PKG_CONFIG_PATH` (a template ships as
[`cryptolib/cryptolib_c.pc.in`](cryptolib/cryptolib_c.pc.in)), build with the tag:

```sh
go build -tags cryptolib_pkgconfig ./...
```

### 4. Fully static — zero runtime library (recommended for deployment)

The most convenient option: link everything (the C ABI **and** libsodium,
liboqs, blst, libcrypto, libsecp256k1) into the binary. The result has **no
`libcryptolib_c` dependency at all** — nothing to ship alongside it, no rpath, no
`DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`. It just runs, anywhere.

```sh
scripts/build_static_archive.sh           # builds build/static/libcryptolib_c.a
go build -tags cryptolib_static ./...
# or, in one step:  make go-static
```

Verify it carries nothing extra:

```sh
otool -L your-binary   # macOS  → only /usr/lib/* system libs
ldd    your-binary     # Linux  → no libcryptolib_c
```

Only the C++ runtime (`libc++`/`libstdc++`) stays dynamic — it's present on
every macOS and Linux system.

> **cgo is required.** Building with `CGO_ENABLED=0` fails fast with a clear
> message (`cryptolib_requires_cgo__rebuild_with_CGO_ENABLED_1`) rather than a
> confusing wall of linker errors. cgo is on by default unless cross-compiling.

---

## Quick start

```go
package main

import (
	"fmt"

	"github.com/Crdzbird/CryptoLib/bridge/bindings/go/cryptolib"
)

func main() {
	if err := cryptolib.Init(); err != nil { // once, at startup
		panic(err)
	}

	// Authenticated symmetric encryption.
	key, _ := cryptolib.SymKeygen()
	ct, _ := cryptolib.XChaCha20Encrypt([]byte("hello"), key, nil)
	pt, _ := cryptolib.XChaCha20Decrypt(ct, key, nil)
	fmt.Printf("%s\n", pt) // hello

	// Ed25519 signatures.
	kp := cryptolib.Ed25519Keygen()
	sig, _ := cryptolib.Ed25519Sign([]byte("msg"), kp.Secret)
	fmt.Println(cryptolib.Ed25519Verify([]byte("msg"), sig, kp.Public)) // true

	// EVM ecrecover.
	ec := cryptolib.Secp256k1Keygen()
	digest, _ := cryptolib.Keccak256([]byte("tx"))
	s, _ := cryptolib.Secp256k1Sign(digest, ec.Secret) // 65 bytes: r‖s‖v
	signer, _ := cryptolib.Secp256k1Recover(digest, s)
	fmt.Println(string(signer) == string(ec.Public)) // true
}
```

More runnable, output-verified snippets live in
[`cryptolib/example_test.go`](cryptolib/example_test.go) and render on
pkg.go.dev.

---

## Feature map

| Domain | Functions / types |
| --- | --- |
| Hashing | `Blake2b`, `Blake3`, `Blake3Keyed`, `Blake3DeriveKey`, `SHA256`, `SHA512`, `HmacSHA256/512`, `Hkdf{Extract,Expand,Derive}`, `Argon2id*` |
| Symmetric AEAD | `XChaCha20Encrypt/Decrypt`, `AES256GCMEncrypt/Decrypt`, `CommittingEncrypt/Decrypt`, `StreamEncryptor`/`StreamDecryptor` |
| Asymmetric | `Ed25519*`, `X25519Keygen`/`X25519SharedSecret`, `Box*`, sealed boxes |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, `HybridKemKeygen` (X25519+ML-KEM-768), `HybridSigKeygen` (Ed25519+ML-DSA-65) |
| BLS12-381 | `BlsKeygen`, `BlsSign`, `BlsVerify`, `BlsAggregate`, `BlsAggregateVerify`, `BlsKeygenFromIkm` |
| Vault / Keyring | `Vault` (KDF→integrity→AEAD→signature), `Keyring` (revocable device/passphrase slots) |
| Media entropy | `EntropyFromFiles`, `EntropyFromFilesDeterministic`, `Entropy` derivations |
| EVM / Bitcoin | `Keccak256`, `Ripemd160`, `Secp256k1Keygen/Pubkey/Sign/Verify/Recover` |

---

## Usage notes

**Initialise once.** Call `cryptolib.Init()` before the first crypto call.

**Errors, not panics.** Fallible calls return `([]byte, error)`. Empty or
malformed input yields an error — the binding never panics on bad input.
Verification helpers (`Ed25519Verify`, `Secp256k1Verify`, `HmacSHA256Verify`, …)
return a `bool` and compare in constant time in the native layer.

**Memory.** Output buffers are copied into garbage-collected Go slices; the
native allocation is freed immediately on every path. You never free anything
manually. Secrets are zeroised on free inside the library.

**Handles.** `StreamEncryptor`, `StreamDecryptor`, `Vault`, `Keyring` and
`Entropy` wrap native handles. Always `Close()` them (use `defer`):

```go
v, err := cryptolib.NewVault(masterKey, cryptolib.KdfSensitive)
if err != nil { /* ... */ }
defer v.Close()
```

`Close` is idempotent and cancels the object's finalizer, so an explicit close
followed by GC cannot double-free. A finalizer exists as a safety net, but
relying on it is discouraged — close deterministically.

**Concurrency.** Stateless top-level functions are safe to call from many
goroutines. The handle types hold mutable native state and are **not** safe for
concurrent use of the *same* handle — use one per goroutine or guard with a
mutex.

**secp256k1 signature lengths.** `Secp256k1Sign` returns a 65-byte recoverable
signature (`r‖s‖v`). `Secp256k1Verify` expects the 64-byte compact form, so drop
the recovery byte: `Secp256k1Verify(digest, sig[:64], pub)`.

---

## Testing

The package ships a race-tested robustness suite (finalizer use-after-free,
double-free on `Close`, handle data races, empty-input safety) plus
output-verified examples:

```sh
# macOS
DYLD_LIBRARY_PATH=../../../build/release go test -race ./cryptolib
# Linux
LD_LIBRARY_PATH=../../../build/release  go test -race ./cryptolib
```

## License

MIT. See the repository [`LICENSE`](../../../LICENSE).
