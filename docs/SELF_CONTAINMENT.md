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
macOS) `Security`/`CoreFoundation` (SIP-protected system frameworks). This removes
the entire runtime library-substitution attack class (`DYLD_INSERT_LIBRARIES`,
planted `libsodium`, version skew).

**Verified:** a program linked fully against the static archive runs correctly,
its `otool -L` shows only system libraries, and it **passes the hard audit**.

### Sealed libcrypto (no-sock, no-dso)

Stock OpenSSL's `libcrypto` contains socket-capable BIO code and a dynamic-loader
(dlopen) subsystem. Static-linking stock libcrypto drags those in as latent
capability (the static binary would import `socket`/`sendto`/`dlopen`). These are
`#ifdef`'d out of the OpenSSL core, so they can only be removed at **configure
time**, not by surgery on a prebuilt archive.

`scripts/build_openssl_nosock.sh` therefore builds `libcrypto.a` from **pinned,
checksum-verified** OpenSSL source configured `no-sock no-dso`, and
`build_static_archive.sh` links that by default (set `CRYPTOLIB_SEALED_OPENSSL=0`
to fall back to the system libcrypto). OpenSSL 3.x has a stable ABI across the
series, so the sealed libcrypto links cleanly with the prebuilt `liboqs.a`.

**Verified:** the sealed `libcrypto.a` has **0** network-syscall and **0** dlopen
references; a binary linked fully against the sealed static archive runs
correctly and **passes the hard audit with no networking, exec, or dlopen
symbols** (only a benign `getenv` from OpenSSL config-reading remains, watch-listed).

## Trade-off

Static linking means **you own patching**: a CVE in a bundled dependency requires
a rebuild + re-ship rather than a system update. Pair the static artifact with
pinned dependency versions, an SBOM, and CVE monitoring.
