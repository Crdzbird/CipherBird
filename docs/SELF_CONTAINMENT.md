# Self-Containment & Ambient-Authority Posture

A cryptography library should be a **sealed compute unit**: it takes bytes in and
returns bytes out, brings everything it needs, and offers no channel through
which key material or plaintext could leak. This document records the measures
that enforce that, and their verified state.

## 1. No ambient authority (the "let nothing out" half)

The C++ core and the C-ABI bridge contain **no** networking, process-execution,
or environment-reading code. This is enforced mechanically, not by inspection:

- `scripts/audit_symbols.sh` (run via `make audit`) inspects the built library's
  imported symbols and **fails the build** if it finds any networking or
  process-execution symbol (`socket`, `connect`, `system`, `popen`, `exec*`,
  `fork`, …). So a future change can never *silently* add an exfiltration path.
- `dlopen`/`getenv` are watch-listed (reported, non-fatal) because OpenSSL uses
  them internally; they must originate from a vetted dependency, not new code.

**Verified:** the shipped shared library `libcryptolib_c.dylib` imports none of
the forbidden symbols. Secrets are also excluded from core dumps — `SecureBuffer`
locks pages with `sodium_mlock`, which marks them `MADV_DONTDUMP`.

## 2. Minimal surface

- **Exports:** only the `cryptolib_*` C ABI is exported (145 symbols). Every
  statically-linked dependency symbol (liboqs, blst, …) is hidden via an
  exported-symbols list (macOS) / version script (ELF). Down from 1757.
- **libcrypto only:** we link OpenSSL's `libcrypto` (EVP: AES-256-GCM-SIV,
  ML-KEM/ML-DSA/SLH-DSA), never `libssl` — the TLS/X.509 stack is not linked.
- **Exploit mitigations:** `-fstack-protector-strong`, `-fstack-clash-protection`,
  `-fcf-protection` (feature-detected), `_FORTIFY_SOURCE=2`; ELF builds add full
  RELRO (`-z relro -z now`) and `-z noexecstack`.

## 3. Bring everything it needs (the static artifact)

`scripts/build_static_archive.sh` produces a single `build/static/libcryptolib_c.a`
merging the bridge with every dependency's static archive (libsodium, BLAKE3,
liboqs, libcrypto, blst, libsecp256k1). A binary linking it has **no Homebrew /
third-party dynamic dependencies** — only the OS's `libSystem`, `libc++`, and (on
macOS) `Security`/`CoreFoundation`. This removes the entire runtime
library-substitution attack class (`DYLD_INSERT_LIBRARIES`, planted `libsodium`,
version skew).

**Verified:** a program linked fully against the static archive runs correctly
and its `otool -L` shows only system libraries.

### Known residual: OpenSSL BIO sockets in the static build

Stock OpenSSL's `libcrypto` contains socket-capable BIO code (23 network symbol
references). When statically linked, some of it is pulled in, so the fully-static
binary *imports* `socket`/`sendto`/etc. — **dormant** code that no CryptoLib path
invokes (attributed: the symbols come only from libcrypto, none from our code or
the other four dependencies). The shared dylib is unaffected (libcrypto is
external there).

To eliminate the dormant socket (and dynamic-loader) code and get a static binary
that passes the hard audit cleanly, build OpenSSL with **`no-sock no-dso`** and
link that `libcrypto.a`. This is the recommended path for a maximally sealed
static distribution; it is not yet wired into the default build.

## Trade-off

Static linking means **you own patching**: a CVE in a bundled dependency requires
a rebuild + re-ship rather than a system update. Pair the static artifact with
pinned dependency versions, an SBOM, and CVE monitoring.
