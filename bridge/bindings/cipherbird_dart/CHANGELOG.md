## 1.1.1

Engine hardening and smaller binaries; no API or wire-format change.

- Vault packets whose signature is not 64 bytes are rejected before
  verification, in packet parsing and in the symmetric and asymmetric vault
  open paths; a short signature previously reached the verifier and could
  crash the process. The asymmetric vault also checks the sender, recipient
  and secret key lengths on seal and open.
- Length arithmetic in the suite, session and Flagship parsers is done in
  `size_t`, so a signature or ciphertext length near 2^32 can no longer wrap
  a bounds check. The suite requires the exact hybrid signature size.
  Regression tests cover both findings and the related short-input cases.
- Both bundled engines are rebuilt. The WebAssembly engine (4.4 MB) uses
  libsodium 1.0.22 and OpenSSL 3.5.9 (3.5 LTS) with OpenSSL trimmed to the
  EVP ciphers the engine uses. The macOS library comes from the host
  toolchain with libsodium 1.0.22, liboqs 0.16.0 and the sealed OpenSSL
  3.6.3 build.
- `CipherBird.ready` completes when the engine is usable: immediately on
  native platforms, after the WebAssembly engine is compiled on the web.
  Concurrent loads are shared. `preload` returns immediately on native
  platforms and is kept for apps that already call it.
- The C ABI is unchanged at 265 functions and the generated web shim is
  identical to 1.1.0.

## 1.1.0

Web support. The engine is compiled to WebAssembly and bundled under
`lib/assets/`; the same API runs in the browser with `dart compile js` or
`dart compile wasm`, with byte-compatible envelopes, signatures and keys.
`CipherBird.preload()` loads the engine and is required on the web; it takes
an optional `library` location. File-path APIs are unavailable in the
browser. AES-256-GCM gained a portable OpenSSL path for CPUs without AES
instructions.

Off-thread work is now described by `CipherBirdJob`, plain data a runner can
copy into an isolate or post to a worker. `CipherBirdRunner.run` takes a job
instead of a function and a message, and the three Argon2id jobs behind the
asynchronous easy-mode helpers are public. In the browser
`CipherBirdIsolateRunner` runs jobs in a web worker shipped under
`lib/assets/`, so password hashing no longer blocks the page.

## 1.0.0

First release. `cipherbird_dart` is the plain-Dart twin of the `cipherbird`
Flutter plugin: the same generated source tree and API, with the native
native engine bundled under `native/<os>-<arch>/` for the host platform
and resolved automatically through the package configuration. Every public identifier carries the package name: `CipherBird`, `CipherBirdRecipe`,
`CipherBirdRunner`, `CipherBirdIsolateRunner`, `CipherBirdInlineRunner` and the
`CipherBird*` extension groups. Error messages start with `cipherbird:` and the
library path override is `CIPHERBIRD_LIBRARY` (`CRYPTOLIB_DYLIB` still works). It replaces
the repository's earlier internal `cryptolib_dart` verification package.
