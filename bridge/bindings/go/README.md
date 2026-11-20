# CipherBird for Go

Idiomatic Go bindings for **CipherBird**, a header-only C++20 cryptography
library exposed through a stable C ABI (`libcipherbird_c`). One import gives you
authenticated encryption, signatures, key exchange, **post-quantum** KEMs and
signatures, sealed messaging, a forward-secret session ratchet, HPKE, Noise,
tokens, P-256, threshold and zero-knowledge signatures, **BLS** aggregation,
password hashing, a layered vault pipeline, composable recipes, a revocable
keyring, steganography, media-derived entropy, and **EVM/Bitcoin** primitives
(Keccak-256, RIPEMD-160, secp256k1 ECDSA).

```go
import "github.com/Crdzbird/CipherBird/bridge/bindings/go/cipherbird"
```

> Uses **cgo**. You need `CGO_ENABLED=1` (the default) and a built copy of the
> native library `libcipherbird_c` at link and run time.

---

## Install

```sh
go get github.com/Crdzbird/CipherBird/bridge/bindings/go/cipherbird
```

## Prerequisites: build the native library

The Go package links against `libcipherbird_c`, which bundles libsodium, liboqs,
blst, OpenSSL libcrypto and libsecp256k1. Build it once from the CipherBird repo:

```sh
cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target cipherbird_c
```

This produces `build/release/libcipherbird_c.{dylib,so}`.

## Linking

The package links in one of five ways, chosen by build tag.

### 1. Default: in-repo paths (no tags)

Inside the CipherBird repository it works out of the box: the header is found at
`bridge/cipherbird_c.h` and the library at `build/release/`. The build also
records an rpath to `build/release`, so a binary built here runs with no loader
path set:

```sh
cd bridge/bindings/go
go run ./example
```

The same holds for a project that reaches this module through a `replace`
directive pointing at a checkout: build the library there (`make lib`) and the
project links and runs against it.

### 2. External module: point cgo at your build

When you `go get` this package into another project, the prebuilt library is not
part of the Go module. Tell the toolchain where your `libcipherbird_c` lives:

```sh
export CGO_LDFLAGS="-L/opt/cipherbird/lib"
export CGO_CFLAGS="-I/opt/cipherbird/include"   # only if the header moved
export DYLD_LIBRARY_PATH=/opt/cipherbird/lib    # macOS, run time
export LD_LIBRARY_PATH=/opt/cipherbird/lib      # Linux, run time
go build ./...
```

### 3. pkg-config (system install)

If the library is installed system-wide with a `cipherbird_c.pc` on your
`PKG_CONFIG_PATH` (a template ships as
[`cipherbird/cipherbird_c.pc.in`](cipherbird/cipherbird_c.pc.in)), build with the tag:

```sh
go build -tags cipherbird_pkgconfig ./...
```

### 4. Fully static: no runtime library (recommended for deployment)

The most convenient option: link everything (the C ABI **and** libsodium,
liboqs, blst, libcrypto, libsecp256k1) into the binary. The result has **no
`libcipherbird_c` dependency at all**: nothing to ship alongside it, no rpath, no
`DYLD_LIBRARY_PATH`/`LD_LIBRARY_PATH`. It just runs, anywhere.

```sh
scripts/build_static_archive.sh           # builds build/static/libcipherbird_c.a
go build -tags cipherbird_static ./...
# or, in one step:  make go-static
```

Verify it carries nothing extra:

```sh
otool -L your-binary   # macOS: only /usr/lib/* system libs
ldd    your-binary     # Linux: no libcipherbird_c
```

Only the C++ runtime (`libc++`/`libstdc++`) stays dynamic; it is present on
every macOS and Linux system.

### 5. Vendored archive inside the module

`make bundle` copies the same static archive and the header into
`cipherbird/native/`, and the `cipherbird_vendored` tag links them from there, so
the build needs nothing outside the module directory:

```sh
make bundle
go build -tags cipherbird_vendored ./...
```

The archive is for the host platform and is not committed on `main`;
[`PUBLISHING.md`](../../../PUBLISHING.md) describes how a release tag carries
it.

### The bank profile

When the linked library was built with `CIPHERBIRD_PROFILE=bank`, add
`-tags cipherbird_bank` to any of the configurations above. The tag leaves out
the calls that profile does not export (media entropy, steganography, the DRBGs
and sntrup761).

> **cgo is required.** Building with `CGO_ENABLED=0` fails fast with a clear
> message (`cipherbird_requires_cgo__rebuild_with_CGO_ENABLED_1`) rather than a
> confusing wall of linker errors. cgo is on by default unless cross-compiling.

---

## Quick start

```go
package main

import (
	"fmt"

	"github.com/Crdzbird/CipherBird/bridge/bindings/go/cipherbird"
)

func main() {
	if err := cipherbird.Init(); err != nil { // once, at startup
		panic(err)
	}

	// Authenticated symmetric encryption.
	key, _ := cipherbird.SymKeygen()
	ct, _ := cipherbird.XChaCha20Encrypt([]byte("hello"), key, nil)
	pt, _ := cipherbird.XChaCha20Decrypt(ct, key, nil)
	fmt.Printf("%s\n", pt) // hello

	// Ed25519 signatures.
	kp := cipherbird.Ed25519Keygen()
	sig, _ := cipherbird.Ed25519Sign([]byte("msg"), kp.Secret)
	fmt.Println(cipherbird.Ed25519Verify([]byte("msg"), sig, kp.Public)) // true

	// EVM ecrecover.
	ec := cipherbird.Secp256k1Keygen()
	digest, _ := cipherbird.Keccak256([]byte("tx"))
	s, _ := cipherbird.Secp256k1Sign(digest, ec.Secret) // 65 bytes: r || s || v
	signer, _ := cipherbird.Secp256k1Recover(digest, s)
	fmt.Println(string(signer) == string(ec.Public)) // true
}
```

More runnable, output-verified snippets live in
[`cipherbird/example_test.go`](cipherbird/example_test.go) and render on
pkg.go.dev. Whole programs sit next to the package: [`example`](example) (the
basics), [`showcase`](showcase) (every capability family), [`sealed`](sealed)
(Flagship and Fortress sealed messaging), [`recipes`](recipes) (composed
pipelines), and [`server`](server) with [`client`](client) (a LavaRand entropy
service over HTTP).

---

## Feature map

| Domain | Functions / types |
| --- | --- |
| Hashing | `Blake2b`, `Blake3`, `Blake3Keyed`, `Blake3DeriveKey`, `NewBlake3Hasher` (incremental), `SHA256`, `SHA512`, `HmacSHA256/512`, `Hkdf{Extract,Expand,Derive}`, `Argon2id*` |
| Symmetric AEAD | `XChaCha20Encrypt/Decrypt`, `AES256GCMEncrypt/Decrypt`, `CommittingEncrypt/Decrypt`, `StreamEncryptor`/`StreamDecryptor` |
| Asymmetric | `Ed25519*`, `X25519Keygen`/`X25519SharedSecret`, `Box*`, sealed boxes |
| Post-quantum | ML-KEM, ML-DSA, SLH-DSA, `HybridKemKeygen` (X25519+ML-KEM-768), `HybridSigKeygen` (Ed25519+ML-DSA-65), `SntrupX25519*` |
| Sealed messaging | `NewIdentity`, `Identity.Seal/Open`, `SealedInspect`, `SealedAddressedTo`, `StreamSealer`/`StreamOpener` (the Flagship and Fortress tiers) |
| Sessions | `GenerateSessionPrekey`, `InitiateSession`, `AcceptSession`, `Session.Encrypt/Decrypt` (post-quantum forward-secret ratchet); `NewNoise` (Noise XX) with `Split`, `Encrypt`, `Decrypt`, `DecryptAt` |
| HPKE (RFC 9180) | `HpkeKeygen`, `HpkeDeriveKeyPair`, `HpkeSetupS`, `HpkeSetupR`, `HpkeContext.Seal/Open/Export`, `HpkeSealBase`, `HpkeOpenBase` |
| Threshold and zero knowledge | `Frost*` (FROST Ed25519 t-of-n, RFC 9591), `Ecvrf*` (RFC 9381), `Bbs*` (selective disclosure, pseudonyms, blind issuance), `Oprf*` (RFC 9497), `Opaque*` (password-authenticated key exchange) |
| BLS12-381 | `BlsKeygen`, `BlsSign`, `BlsVerify`, `BlsAggregate`, `BlsAggregateVerify`, `BlsKeygenFromIkm` |
| Vault / Keyring | `Vault` (KDF, integrity, AEAD, signature), `AsymVaultSeal/Open`, `Keyring` (revocable device/passphrase slots) |
| Recipes and envelopes | `NewRecipe`, `MaximumSecurity`, `SecurityProfile`, `RegisterLayer`; `MolecularSeal/Open` (and `WithKey`), `Suite*` |
| Steganography | `StegoEmbed/Extract` (plain, keyed, encrypted), `StegoCapacity`, `StegoInspect`, `StegoDetectHidden`, `HpkeStegoSeal/Open`, `FecEncode/Decode` |
| Media entropy and DRBGs | `EntropyFromFile(s)`, `EntropyFromFilesDeterministic`, `Entropy` derivations, `AssessFileHealth`, `NewDrbg`, `NewFortuna` |
| P-256 (ES256) | `P256GenerateKey`, `P256PublicKey`, `P256Sign`, `P256Verify` (raw `r \|\| s`, SHA-256, RFC 6979 nonces), `P256PrivateKeyFromPKCS8`, `P256PrivateKeyFromPEM`, `P256Available`; see `docs/P256.md` |
| Tokens | `TokenFormats`, `TokenKeygen`, `TokenIssue`, `TokenAccept`, `TokenAcceptTo`, `TokenPeekFormat`, `TokenPeekFooter` for any format by name (`v4.local`, `cb1.local`, `cb1.public`; see `docs/TOKEN_API.md`); `PasetoV4LocalEncrypt/Decrypt`, `Cb1LocalEncrypt/Decrypt`, `Cb1PublicSign/Verify` are the same calls with the format fixed |
| EVM / Bitcoin | `Keccak256`, `Ripemd160`, `Secp256k1Keygen/Pubkey/Sign/Verify/Recover` |

---

## Usage notes

**Initialise once.** Call `cipherbird.Init()` before the first crypto call.

**Errors, not panics.** Fallible calls return `([]byte, error)`. Empty or
malformed input yields an error; the binding never panics on bad input.
Verification helpers (`Ed25519Verify`, `Secp256k1Verify`, `HmacSHA256Verify`
and the rest) return a `bool` and compare in constant time in the native layer.

**Memory.** Output buffers are copied into garbage-collected Go slices; the
native allocation is freed immediately on every path. You never free anything
manually. Secrets are zeroised on free inside the library.

**Handles.** `StreamEncryptor`, `StreamDecryptor`, `Vault`, `Keyring`,
`Entropy`, `Session`, `Noise`, `HpkeContext`, `Blake3Hasher`, `Drbg`, `Fortuna`
and the sealed `StreamSealer`/`StreamOpener` wrap native handles. Always
`Close()` them (use `defer`):

```go
v, err := cipherbird.NewVault(masterKey, cipherbird.KdfSensitive)
if err != nil { /* ... */ }
defer v.Close()
```

`Close` is idempotent and cancels the object's finalizer, so an explicit close
followed by GC cannot double-free. A finalizer exists as a safety net, but
relying on it is discouraged: close deterministically.

**Concurrency.** Stateless top-level functions are safe to call from many
goroutines, a process's first calls included. The handle types hold mutable
native state and are **not** safe for concurrent use of the *same* handle: use
one per goroutine or guard with a mutex.

On macOS, engines before the 1.5.0 thread fixes could hang here: a thread
waiting for one of OpenSSL's locks while a signal reached it could miss its
wakeup, and the Go runtime signals its threads constantly, so the first
concurrent `P256Sign` calls of a server (and the AES-GCM, GCM-SIV, HPKE, X-Wing
and post-quantum calls) stopped forever. The engine now does OpenSSL's
first-use work once in `Init`, holds signals back while a thread is inside
OpenSSL and shields a thread's exit. Rebuild the native library (`make lib`)
after updating this module; `docs/P256.md` has the details under "Threads".

**ES256 for a JWT.** `P256Sign` hashes the message with SHA-256 and returns the
raw 64-byte `r || s` a JWS carries; load an Apple `.p8` key with
`P256PrivateKeyFromPEM`:

```go
key, err := cipherbird.P256PrivateKeyFromPEM(p8)
if err != nil { /* ... */ }
defer cipherbird.Secret(key.Secret).Wipe()
sig, err := cipherbird.P256Sign(key.Secret, []byte(header+"."+claims))
jwt := header + "." + claims + "." + base64.RawURLEncoding.EncodeToString(sig)
```

`P256Available()` is false when the linked library was built without OpenSSL's
elliptic curves; the default `build/release` library and the sealed static
archive both have them.

**secp256k1 signature lengths.** `Secp256k1Sign` returns a 65-byte recoverable
signature (`r || s || v`). `Secp256k1Verify` expects the 64-byte compact form, so drop
the recovery byte: `Secp256k1Verify(digest, sig[:64], pub)`.

---

## Testing

The package ships a race-tested robustness suite (finalizer use-after-free,
double-free on `Close`, handle data races, empty-input safety) plus
output-verified examples:

```sh
# macOS
DYLD_LIBRARY_PATH=../../../build/release go test -race ./cipherbird
# Linux
LD_LIBRARY_PATH=../../../build/release  go test -race ./cipherbird
```

## License

MIT. See the repository [`LICENSE`](../../../LICENSE).
