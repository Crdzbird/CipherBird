## 1.1.0

Web support. The engine is compiled to WebAssembly and bundled under
`lib/assets/`; the same API runs in the browser with `dart compile js` or
`dart compile wasm`, with byte-compatible envelopes, signatures and keys.
`CipherBird.preload()` loads the engine and is required on the web; it takes
an optional `library` location. File-path APIs are unavailable in the browser
and the isolate runner executes inline there. AES-256-GCM gained a portable
OpenSSL path for CPUs without AES instructions.

## 1.0.0

First release. `cipherbird_dart` is the plain-Dart twin of the `cipherbird`
Flutter plugin: the same generated source tree and API, with the native
native engine bundled under `native/<os>-<arch>/` for the host platform
and resolved automatically through the package configuration. Every public identifier carries the package name: `CipherBird`, `CipherBirdRecipe`,
`CipherBirdRunner`, `CipherBirdIsolateRunner`, `CipherBirdInlineRunner` and the
`CipherBird*` extension groups. Error messages start with `cipherbird:` and the
library path override is `CIPHERBIRD_LIBRARY` (`CRYPTOLIB_DYLIB` still works). It replaces
the repository's earlier internal `cryptolib_dart` verification package.
