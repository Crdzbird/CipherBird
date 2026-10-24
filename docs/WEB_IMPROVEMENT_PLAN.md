# Web improvement plan

Written 2026-10-24 against cipherbird 1.2.0 plus the entropy stage on main
(C ABI 327 symbols, WebAssembly engine 4.5 MB). It states where the browser
build stands, what holds it back, and six phases that close the gaps in
the order that pays off soonest. Each phase names its deliverables, how it
is verified, and what stays out of reach, so the plan can be executed one
phase at a time and the state of the web build read off the headings.

## 1. Where the web build stands

The engine is `bridge/cryptolib_c.cpp` compiled by Emscripten with every
dependency built for wasm32 (libsodium, BLAKE3, secp256k1, blst, OpenSSL,
liboqs with ML-KEM, ML-DSA, SLH-DSA and sntrup761), linked at -O3 with
wasm exceptions, an 8 MB stack, memory growth to 4 GB, no SIMD and no
threads. The Dart packages reach it through a dart:ffi-shaped shim
(`lib/src/platform/web`) generated from the C header, so the 280-part API
layer compiles unchanged for the browser. Loading fetches `cipherbird.js`
and `cipherbird.wasm` with subresource integrity digests from
`engine_integrity.dart` and instantiates from the verified bytes; a page
can boot the engine before Flutter through two script tags that
`dart run cipherbird:web_setup` inserts. One worker exists, hand-written in
`cipherbird_worker.js`, and runs three Argon2id jobs off the main thread.
The approval boundary admits the web build for ephemeral data only.

What works in the browser today: every primitive, every envelope (Suite,
Suite v2, Session v1 and v2, HPKE with any KEM, X-Wing, the recipes with a
passphrase or a raw key), FROST, BBS, OPRF, OPAQUE, Noise, the keyring
without hardware slots, the live entropy source fed from bytes, and the
Flutter plugin and the Dart twin test suites under dart2js and dart2wasm.

### 1.1 The gaps, measured

Speed against the native engine on the same machine (results.md, 1 MiB
inputs where applicable):

| Operation | native | WebAssembly | ratio |
|---|---|---|---|
| SHA-256 | 217 MB/s | 63 MB/s | 3.4x slower |
| BLAKE3 | 820 MB/s | 72 MB/s | 11x slower |
| XChaCha20-Poly1305 | 296 MB/s | 63 MB/s | 4.7x slower |
| AES-256-GCM | 651 MB/s | 39 MB/s | 17x slower |
| Argon2id 64 MiB | 70.7 ms | 84.3 ms | 1.2x slower |
| ML-KEM-768 round trip | 71 us | 204 us | 2.9x slower |
| ML-DSA-65 sign | 433 us | 473 us | 1.1x slower |

The browser's own crypto, reached by the `cryptography` package through
WebCrypto, runs SHA-256 at 1452 MB/s and AES-256-GCM at 1708 MB/s, 23x and
44x ahead of the engine, because it is native code with hardware AES and
SHA. The engine's bulk symmetric work is where the browser is weakest and
where the fix is cheapest.

Functionality: 32 C ABI entry points take a file path and therefore fail
in the browser, where there is no file system: steganography (embed,
extract, capacity, inspect, detect, content digest, keyed and encrypted
forms), media entropy (`entropyFromFile*`, `keyFromFile`, `sealFromFile`,
`assessFileHealth`), the composed seals (physical, HPKE stego, image
factor), the recipe key-file source, and `fips_init`. The example app's
Steganography and LavaRand playgrounds report themselves unsupported on
the web for that reason, while Live entropy works because it takes bytes.

Responsiveness: everything except Argon2id runs on the main thread. An
SLH-DSA signature, a maximum-profile recipe, a Session v2 handshake and a
steganographic embed each block the page for tens to hundreds of
milliseconds, which shows as a frozen animation or a late tap.

Size: 4.5 MB of wasm plus 108 KB of JavaScript, served uncompressed by a
default static host (roughly 1.3 MB under Brotli). The archive sizes of
the dependencies point at OpenSSL (5.9 MB) and secp256k1 (1.5 MB) as the
largest contributors before dead-code elimination, with liboqs (540 KB)
carrying twelve SLH-DSA parameter sets most pages never call.

Security posture: the engine's linear memory is readable by any script on
the page, so the approval boundary stops at ephemeral data. There is no
hardware-backed slot for the keyring in the browser and no validated
module behind the FIPS layer, which reports itself absent.

Assurance: the Chrome test runs (`make flutter-web-test`, the twin's
`dart test -p chrome`) are run by hand and are not part of CI; the web
benchmark is a local test. A web regression can reach main unnoticed.

## 2. Principles

1. One API, every platform. A method the browser cannot serve is a bug to
   fix, not a platform note to write, unless the platform truly lacks the
   capability (a file system, a validated module).
2. Same bytes on every platform. Envelopes, signatures, keys and carriers
   produced in the browser must open natively and the other way round; the
   interop harness proves it for each new path.
3. Honest claims. Browser crypto is platform crypto, not a validated
   module; a passkey-bound key is a strong device factor, not a secure
   element. Documentation and `approvedFor` say exactly that.
4. Measured, not asserted. Every phase ends with the web benchmark table
   and the Chrome suites, and the numbers go into results.md.

## 3. Phases

### W1. Bytes everywhere: the media APIs without a file system

Goal: steganography, media entropy and the composed seals work in the
browser on bytes, and the same byte-based API exists natively.

Engine: link with `-sFORCE_FILESYSTEM=1` and export `FS`, so Emscripten's
in-memory file system is available. The C++ keeps its path-based code;
the Dart web platform gains a tiny `MemFs` helper that writes bytes to a
private path (`/cb/<id>.<ext>`), calls the existing path entry point, reads
the result back and unlinks both, wiping the heap pages the file occupied.
The extension matters, since the carriers dispatch on it, so the byte API
takes the format explicitly.

Dart: one new extension per family with byte signatures, implemented
once over a `MediaScratch` seam that is MemFs on the web and a temporary
directory natively: `stegoEmbedBytes(cover, format, payload)` returning the
carrier bytes, `stegoExtractBytes`, `stegoCapacityOf`, `stegoInspectBytes`,
`stegoDetectHiddenBytes`, the keyed and encrypted forms,
`physicalSealBytes`, `hpkeStegoSealBytes`, `imageFactorSealBytes` and their
opens, `entropyFromBytes` (fresh and deterministic, with the policy),
`assessHealthOf(bytes)`, `keyFromBytes`, `sealWithBytes`, and
`KeyBytesSource` for the recipe. The path-based methods stay and, natively,
call the same engine functions as before.

Example: the Steganography and LavaRand playgrounds switch to the byte
API and drop the "unsupported in the browser" branch; the file picker
already returns bytes on every platform. Live entropy gains a browser
camera through `getUserMedia` and a canvas, feeding the luma of each frame
as on the phone.

Verification: the plugin and twin Chrome suites gain the byte-API tests
(a carrier embedded in Chrome opens natively and the reverse, through the
interop harness); the example's playground tests run on Chrome; the
MemFs helper is fuzzed with the stego corpus through the wasm engine in a
node run so the browser build sees the same hardened parsers.

Out of reach: `fips_init` stays native, there is no validated module to
load in a browser.

### W2. Off the main thread by default

Goal: no engine call blocks the page for longer than a frame; the worker
runs every heavy job, not only Argon2id.

The `CipherBirdJob` seam exists (cost, op, arguments, execute, decode) with
three jobs. This phase makes the worker generic: a job carries the C ABI
symbol name and byte or integer arguments, the worker (which holds its own
engine copy) runs the `cbw_` wrapper through the same registry the page
uses, and returns bytes or an error. Jobs are added for the operations
that cost more than a few milliseconds: ML-DSA and SLH-DSA keygen and
sign, hybrid signatures, Argon2id at every profile, the recipes, Suite v2
and Session v2 handshakes, the stego embeds and extracts and the entropy
harvests from W1, and the live source's feed when a frame is large. The
`easy` layer's async methods route through jobs; the synchronous methods
stay for callers that want them. Handles (sessions, keyrings, live
sources) live in one engine only, so a handle created on the page is used
on the page; the job layer refuses to move one and says so.

Verification: a jank test in the example's Chrome run measures the
longest frame while a maximum-profile recipe seals a 1 MiB message with
the generic worker on and off; the number goes into results.md.

Out of reach: true parallelism inside one operation (no pthreads) until
the hosting page sets the cross-origin isolation headers; W4 revisits.

### W3. Speed where the browser is faster

Goal: bulk symmetric work at WebCrypto speed without changing formats.

A `WebCrypto` layer, the browser's counterpart of `DeviceFips`: SHA-256
and SHA-512, HMAC, HKDF, PBKDF2, AES-256-GCM with the engine's own
`[nonce|ciphertext|tag]` layout so envelopes interoperate, ECDH and ECDSA
on P-256, and Ed25519 and X25519 where the browser ships them (Chrome 137
and Safari 17 do, Firefox behind a flag), reported by `WebCrypto.module()`
the way `DeviceFips.module()` reports its providers. Every call is
asynchronous, because WebCrypto is, and the layer is opt-in by method, so
no synchronous engine path changes behaviour. The recipes get an
`AesGcmLayer` variant that uses it in the browser for the AEAD step when
the caller asks, falling back to the engine where WebCrypto lacks the
algorithm.

Engine: `-msimd128` with a measurement of what it buys for BLAKE3 and
ChaCha20 (the portable C has no wasm SIMD paths, so the gain is expected
to be small and is reported, not promised); `-flto` across the archives.

Verification: the web benchmark gains a WebCrypto column; the interop
harness proves an AES-GCM envelope sealed by WebCrypto opens in the native
engine and the reverse.

Honest claim: WebCrypto is the platform's crypto, backed by BoringSSL in
Chromium and CoreCrypto in Safari; it is not a FIPS-validated module as
exposed to pages and the documentation says so.

### W4. A smaller engine, and threads where the host allows

Progress (2026-10-24): OpenSSL trimmed and the small secp256k1 tables
take the engine from 4.78 MB to 2.99 MB at the same speed; the profiling attribution shows
liboqs at 0.25 MB with its SLH-DSA sets sharing code, so the second
module is dropped from the plan. SIMD is on since W3. Threads remain.

Goal: a first paint that does not wait for 4.5 MB, and parallel work for
pages that opt in.

Size: measure the engine with `twiggy` per component, then act on the
largest. Expected moves: drop the secp256k1 precomputed tables in favour
of the smaller configuration already used on Android; trim OpenSSL to the
EVP ciphers and digests the bridge calls (the native builds already do);
keep ML-KEM, ML-DSA and the two 128-bit SLH-DSA sets in the main engine
and move the ten other SLH-DSA sets to a second module loaded on first
use through `WebAssembly.compileStreaming`; compile with `-Oz` for the
parsers and keep `-O3` for the hot primitives. A `bank` web engine (the
bank profile without steganography, media entropy or native combiners) is
produced by the same workflow for banking pages that never need them, and
the loader picks the engine by profile. Serving guidance: Brotli, an
immutable cache header for the digest-named engine, and a preload tag.

Threads: when the page serves the cross-origin isolation headers, a
pthreads build lets Argon2id use its lanes and lets the worker pool run
several jobs at once; the loader detects `crossOriginIsolated` and picks
the threaded engine, otherwise the single-threaded one. Both come from
the Engines workflow with their own attestation and digests.

Verification: engine size and time to first call measured in the Chrome
run on a throttled connection; the threaded engine's Argon2id against the
single-threaded one in the benchmark.

### W5. A better security posture for the browser

Progress (2026-10-24): items 1 (engine-in-worker mode through
`preload(workerOnly: true)`) and 3 (a non-extractable WebCrypto key in
IndexedDB as the browser key module) are built and tested in Chrome, and
the approval boundary admits long-lived keys in worker-only mode (item 5).
Item 2, the passkey slot, and item 4, the header check, remain.

Goal: raise what the web build can honestly be approved for.

1. Engine-in-worker mode: an option to keep the only engine inside the
   worker, so key material never sits in the page's linear memory; the
   page keeps a proxy and every call is asynchronous. Scripts injected into
   the page can still message the worker, so this is defence in depth and
   is described as such.
2. A passkey-bound keyring slot through the WebAuthn PRF extension: the
   authenticator derives a per-credential secret that unlocks a keyring
   slot, giving the browser a device-bound (or passkey-synced) factor
   comparable to the hardware slot on phones. Supported in Chrome and
   Safari 18 and reported through the slot's backing field; the threat
   model records that a synced passkey is not a secure element.
3. Non-extractable WebCrypto wrapping keys for a keyring at rest in
   IndexedDB, so a stored keyring cannot be read out as bytes even by a
   script that reads IndexedDB.
4. Hosting guidance that the loader can check at startup: a Content
   Security Policy without `unsafe-eval` (the engine does not need it),
   Trusted Types, and the isolation headers from W4, with `approvedFor`
   taking them into account.
5. The approval boundary revisited: with 1 to 3 in place and the headers
   present, the web build is approved for `longLivedKeys` under a stated
   residual risk; `cardData` stays refused in the browser.

Verification: the approval tests, a Chrome test that creates and unlocks
a passkey slot with a virtual authenticator, and the updated threat model
section 9.5.

### W6. Assurance and developer experience

Progress (2026-10-24): the web CI job runs both Chrome suites under
dart2js and dart2wasm and enforces a 3.4 MB ceiling on the bundled
engine; `web_setup --check`, the hosting guidance and the Pages workflow
are in. The web benchmark as a CI artifact and the hosted showcase (once
Pages is enabled) remain.

Goal: the browser is a first-class target in CI and easy to adopt.

- A `web` CI job: both packages' Chrome suites under dart2js and
  dart2wasm, the example's playground tests on Chrome, the web benchmark
  as an artifact with a regression threshold on the bulk operations, and
  the engine size as a reported number with a ceiling.
- The showcase published as a static site from the Engines workflow with
  the engine served under its digest, so a developer can try every
  capability in the browser without building.
- Documentation: one "Web" chapter in both READMEs covering the startup
  contract, what runs where, the WebCrypto layer, sizes and hosting
  headers; the per-platform table marks the browser for every method.
- `web_setup` grows a `--check` that reads the page and reports the tags,
  the headers and the CSP it would need.

## 4. Order and effort

| Phase | Why first | Rough effort |
|---|---|---|
| W1 bytes everywhere | the largest functional gap, no new crypto, unblocks the example | 2 sessions |
| W2 worker by default | the largest felt problem, the seam exists | 2 sessions |
| W3 WebCrypto layer | the largest measured gap, formats unchanged | 2 sessions |
| W4 size and threads | needs W2's worker and the Engines workflow | 2 to 3 sessions |
| W5 posture | depends on W2's worker mode | 2 to 3 sessions |
| W6 CI and DX | can start any time, grows with each phase | 1 session plus upkeep |

The Chrome CI job from W6 is small and protects every later phase, so it
is folded into W1's first commit.

## 5. Not planned

- A FIPS layer in the browser: no validated module is exposed to pages.
- Synchronous WebCrypto: the platform API is asynchronous only.
- A fully synchronous engine start: browsers forbid compiling a module
  over 4 KB synchronously on the main thread; the two boot tags remain
  the fastest path.
- Reading or writing the user's files directly from the engine: the byte
  API with the page's own file picker is the browser's model.
