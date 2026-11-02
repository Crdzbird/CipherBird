# Proposed amendment to AUDIT_SCOPE.md: native PASETO v4.local

Status: accepted. Revision 2 of `docs/AUDIT_SCOPE.md` names the commits
(`e3887fb` for this proposal, `a64370c` for the follow-up that closed the
open items and added the cb1 tokens, which stay out of the bank scope).
The text below is the proposal as reviewed.

## 1. What is added

The branch first shipped two building blocks (shape A of the earlier
revision of this proposal): a keyed BLAKE2b with a chosen output length and
a raw, unauthenticated XChaCha20 stream export. It now ships shape B, the
recommended end state: the whole PASETO v4.local construction runs natively
behind four C functions, and the raw stream export is withdrawn.

All of the following compile in the `full` and `bank` profiles (inside
`CRYPTOLIB_HAS_SODIUM_CRYPTO`) and are absent from the `fips` profile like
every other libsodium-backed function.

```c
#define CRYPTOLIB_PASETO_OK            0
#define CRYPTOLIB_PASETO_ERR_INVALID  (-1)
#define CRYPTOLIB_PASETO_ERR_ARGUMENT (-2)
#define CRYPTOLIB_PASETO_ERR_INTERNAL (-3)
#define CRYPTOLIB_PASETO_V4_LOCAL_KEY_BYTES 32
#define CRYPTOLIB_PASETO_V4_MAX_INPUT_BYTES ((size_t)1 << 26)

size_t cryptolib_paseto_v4_local_encrypt_len(size_t msg_len, size_t footer_len);
size_t cryptolib_paseto_v4_local_decrypt_cap(size_t token_len);

int cryptolib_paseto_v4_local_encrypt(
    uint8_t* out, size_t out_cap, size_t* out_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* msg, size_t msg_len,
    const uint8_t* footer, size_t footer_len,
    const uint8_t* implicit, size_t implicit_len);

int cryptolib_paseto_v4_local_decrypt(
    uint8_t* out, size_t out_cap, size_t* out_len,
    const uint8_t* token, size_t token_len,
    const uint8_t* key, size_t key_len,
    const uint8_t* expected_footer, size_t expected_footer_len,
    const uint8_t* implicit, size_t implicit_len);

CryptoBufferResult cryptolib_blake2b_keyed(const uint8_t* msg, size_t msg_len,
                                           const uint8_t* key, size_t key_len,
                                           size_t out_len);
```

`cryptolib_blake2b_keyed` stays because applications use it for keyed
digests and PASERK `k4.lid` identifiers; it no longer serves PASETO itself.
It now hashes straight into the returned malloc'd buffer, without the
intermediate locked `SecureBuffer` it used before.

A fifth function exists only in test builds:

```c
int cryptolib_paseto_v4_local_encrypt_with_nonce_for_testing(
    ...same parameters as encrypt..., const uint8_t* nonce, size_t nonce_len);
```

It is declared and compiled only under `CRYPTOLIB_PASETO_TEST_NONCE`, which
the CMake option of the same name sets. The option is OFF by default and
configuring it with `CRYPTOLIB_PROFILE=bank` or `fips` is a fatal CMake
error, so the bank export list cannot contain it.

The C++ entry point is `crypto::paseto::V4Local` in the new header
`include/cryptolib/paseto.hpp` (`seal`, `open`, `token_len`,
`open_capacity`, and `seal_with_nonce_for_testing` under the test macro),
with the token-text codec in `crypto::paseto::codec` (`encoded_len`,
`encode`, `decode`; see section 2),
included from `cryptolib.hpp` next to `symmetric.hpp`. The
`XChaCha20Stream` class this branch had added to `symmetric.hpp` is
removed; `symmetric.hpp` is unchanged from `main`.

The Go binding gains `PasetoV4LocalEncrypt(key, message, footer, implicit)
(string, error)`, `PasetoV4LocalDecrypt(token, key, expectedFooter,
implicit) ([]byte, error)`, `PasetoV4LocalDecryptTo(out, token, key,
expectedFooter, implicit) (int, error)` (decrypt into a caller buffer, no
Go allocation), the pure-Go length helpers `PasetoV4LocalEncryptLen` and
`PasetoV4LocalDecryptCap` (equal to the C helpers, checked by a test, so
every operation is exactly one cgo call), and the sentinel errors `ErrPasetoInvalid`,
`ErrPasetoKey`, `ErrPasetoArgument` and `ErrPasetoInternal` in
`bridge/bindings/go/cryptolib/paseto_v4.go`; `Blake2bKeyed` stays in
`paseto_primitives.go`; `XChaCha20StreamXOR` is removed. A test-only
`PasetoV4LocalEncryptWithNonceForTesting` exists under the Go build tag
`cryptolib_paseto_test_nonce` and links only against a test build.

Effect on the numbers in AUDIT_SCOPE.md: the bank library exports 275 C
functions (270 before: `cryptolib_blake2b_keyed` and the four PASETO
functions). The bank test binary runs 295 tests (274 before: 5 for keyed
BLAKE2b in `tests/test_paseto_primitives.cpp`, 16 for v4.local in
`tests/test_paseto_v4.cpp`); the full ASan baseline grows by the same 21.
A libFuzzer target, `tests/fuzz/fuzz_paseto_v4.cpp`, joins the
`CRYPTOLIB_FUZZ` build.

## 2. The construction, as implemented

Per the PASETO version 4 specification:

1. `n` = 32 random bytes from libsodium's `randombytes_buf`.
2. `Ek || n2 = BLAKE2b(key = K, msg = "paseto-encryption-key" || n, out = 56)`.
3. `Ak = BLAKE2b(key = K, msg = "paseto-auth-key-for-aead" || n, out = 32)`.
4. `c = XChaCha20(Ek, n2) XOR m` (`crypto_stream_xchacha20_xor`).
5. `t = BLAKE2b(key = Ak, msg = PAE("v4.local.", n, c, f, i), out = 32)`,
   streamed with `crypto_generichash_update`: the fixed 73-byte head (the
   piece count, the header and its length, `n` and its length, and the
   length of `c`) is one update from a stack array, then `c`, then the
   length and bytes of `f` and of `i`. PAE is never materialised.
6. `"v4.local." || b64url(n || c || t)` and, when `f` is not empty,
   `"." || b64url(f)`, unpadded, with `crypto::paseto::codec::encode`.

Decrypt checks the header, splits at the first `.`, rejects an empty footer
segment, requires the presence of a footer to match the presence of an
expected footer, decodes body and footer with
`crypto::paseto::codec::decode` (which rejects padding, foreign
characters, trailing data, a length of 1 mod 4 and non-zero trailing bits,
so only the canonical encoding is accepted), requires at least 64 decoded
bytes, compares the footer with `memcmp`, recomputes the tag over the
token's own footer and the implicit assertion, compares it with
`crypto_verify_32`, and only then decrypts. Every token-dependent failure
returns `CRYPTOLIB_PASETO_ERR_INVALID`. The footer check is strict: an
empty `expected_footer` means the token must carry none. A caller that
selects a key by footer first reads the (untrusted) footer, then passes it
back as the expected one.

Token codec. Until this revision the token text went through libsodium's
constant-time `sodium_bin2base64` and `sodium_base642bin`, which a
per-stage benchmark on an Apple M3 Max measured at about 0.8 us per token
in each direction (0.58 + 0.22 us to encode a 327-character token, 0.67 +
0.16 us to decode it), a quarter of the whole operation. The codec is now a
table-driven one in `crypto::paseto::codec`, about 0.07 us each way. This
gives up constant time on purpose and only for public bytes: the body is
the nonce, the ciphertext and the tag, which are the token on the wire, and
the footer is sent in clear. Keys never pass through it (PASERK key strings
are parsed by the caller). Its acceptance is pinned to libsodium's: a test
compares it with `sodium_base642bin` (URL-safe, unpadded, no ignored
characters) on every 1- and 2-byte input, a fifth of all 3-byte inputs and
200,000 random strings, requiring the same verdict and the same bytes, and
compares `encode` with `sodium_bin2base64` at every length up to 300 in the
in-place layout encrypt uses; the libFuzzer target asserts the same on
every input. The footer comparison moved from `sodium_memcmp` to `memcmp`
for the same reason (both sides are public; about 0.1 us). The tag
comparison stays `crypto_verify_32`.

Not changed, with the reason. The per-key BLAKE2b state is not
precomputed: libsodium's `blake2b_update` buffers up to two blocks and
compresses the key block only once more than 128 further bytes arrive, so
after `crypto_generichash_init` the key block is still uncompressed and a
saved state would save only the parameter setup (about 20 ns) while
keeping a copy of the padded key in another buffer; the state type is
also documented as opaque. The nonce batch stays at 1 KiB: larger batches
measured the same per nonce (about 97 ns, the cost of `arc4random_buf`
per byte), and a user-space generator would be new nonce code.

## 3. Memory, allocation and concurrency

- No allocation and no page locking on either path. The disassembly of the
  bank dylib shows the two exports reach only `crypto_generichash*`,
  `crypto_stream_xchacha20_xor`, `crypto_verify_32`, `sodium_memzero`,
  `randombytes_buf`, `memcpy`, `memcmp`, `memmove`, `memchr`, the inline
  token codec, and once per process `pthread_atfork` and a static guard
  (to be re-confirmed on the frozen commit). `sodium_mlock`, `malloc` and `SecureBuffer` are not reachable.
- The derived `Ek || n2`, `Ak` and the recomputed tag live in one stack
  struct whose destructor calls `sodium_memzero`, so they are wiped on every
  return path. The BLAKE2b state is wiped after use.
- Output goes to the caller's buffer. Encrypt computes `n || c || t` in the
  tail of that buffer and base64-encodes it forward in place: the input
  starts `encoded_len(len) - len` bytes after the output, each 3-byte group
  is read before its 4 characters are written, and the write position
  never passes the unread input. Decrypt decodes into the caller's buffer, verifies, moves the
  ciphertext to the front and decrypts in place. On success the bytes after
  the message, up to `decrypt_cap`, are zeroed; on failure the whole region
  is zeroed. Outputs overlapping any input are rejected.
- Nonces. A single `randombytes_buf` call costs about 1.7 microseconds on
  macOS and is serialised across threads, so encrypt takes nonces from a
  per-thread 1 KiB batch filled by one `randombytes_buf` call. Nonces are
  public, so the batch is not secret; each nonce is zeroed in the batch as
  it is taken. A `pthread_atfork` child handler advances a generation
  counter, and a batch from an older generation is discarded, so a forked
  child never emits a nonce its parent also emits (a test forks and checks
  this; with the handler stubbed out the child does repeat the parent's
  nonce). If `pthread_atfork` fails the code falls back to one
  `randombytes_buf` call per nonce.
- Lengths are validated at the ABI before any read: `key_len` exactly 32;
  message, footer, implicit and expected footer at most 2^26 bytes; a NULL
  pointer only with length 0; `out_cap` at least the size helper's value,
  which depends only on public lengths, so `ERR_ARGUMENT` never depends on
  token content. A token longer than the longest valid token, or too short
  to be one, is `ERR_INVALID`.

## 4. Misuse risk after this change

The bank build again has no unauthenticated encryption export: the raw
stream, the tag comparison and nonce generation are all inside the library,
which removes the three failure modes that only a caller could get right
before (verify before decrypt, constant-time comparison, nonce freshness).
What remains:

- `cryptolib_blake2b_keyed` still accepts `out_len` down to 1 and an empty
  key. It is documented as a keyed digest, not a MAC constructor, and
  PASETO no longer depends on it.
- `encrypt_with_nonce_for_testing` reuses a keystream if a caller repeats
  a nonce. It cannot appear in a bank or fips build, and its name says
  what it is for.
- The footer is authenticated but not encrypted; applications must not put
  secrets in it (PASETO's own rule).

## 5. Evidence on this branch

- Official vectors: `tests/vectors/paseto/v4.json` (paseto-standard,
  sha256 `0b72948b65d1f73f574c9ad2aa3481ec27bf8c632f5f6e1596cd41f5b9703387`)
  is vendored. The C++ test `paseto_v4/official-vectors` (formerly
  `official-vectors-if-vendored`, which skipped when the file was missing,
  required only one vector to run, counted 4-F-1 without decrypting it and
  accepted any non-OK code for the failure vectors) and the Go test
  `TestPasetoV4LocalOfficialVectors` now fail when the file is missing or
  its hash differs, require exactly the 14 vectors `4-E-1` to `4-E-9` and
  `4-F-1` to `4-F-5` in order, decrypt all nine `4-E` vectors to their
  payloads (and rebuild each with the in-test reference), require
  `CRYPTOLIB_PASETO_ERR_INVALID` for 4-F-2 to 4-F-5, and in a
  `CRYPTOLIB_PASETO_TEST_NONCE` build require all nine to re-encrypt byte
  for byte. 4-F-1 (a v4.public key used as a v4.local key) tests key
  typing, which a raw-byte ABI cannot see; the tests assert its shape and
  say so, and the EuroRail server tests it at its PASERK parser. Moving the
  file away or renaming one vector makes the test fail (checked).
- Cross-implementation check (outside the repository): tokens from the
  native code, from a verbatim copy of the EuroRail server's Go
  implementation and from an independent `golang.org/x/crypto` reference
  decrypt in every pairing, across message, footer and implicit sizes;
  wrong keys, wrong implicit assertions and every single-byte tamper are
  rejected by all three; with the test nonce, the three produce
  byte-identical tokens.
- In-repository tests: round trips at every length residue, a 1 MiB message
  across encoder chunks, interoperation with an in-test reference built
  from libsodium primitives, every token byte and every decoded byte
  tampered, wrong key, footer and implicit assertion, non-canonical and
  malformed base64, header variants, truncation at every length, empty and
  oversize inputs, ABI argument validation, wiping of the output region,
  nonce uniqueness across batch refills and threads, and fork behaviour.
- BLAKE2b at 32, 56 and 64 bytes against libsodium 1.0.22's
  `test/default/generichash.exp`, the BLAKE2 reference keyed vectors,
  Python `hashlib` and Go `x/crypto/blake2b` (unchanged from the earlier
  revision).
- Bank, full and bank ASan/UBSan C++ suites, the test-nonce suite, the
  libFuzzer target, and the Go suite with `go vet` pass.
- `scripts/audit_symbols.sh` on the bank library FAILS, and did before this
  revision: its `HARD` pattern is not anchored at the start, so
  `_pthread_atfork` (the nonce batch's fork handler, which spawns nothing)
  matches `fork$`. With the two patterns anchored (`^_?(...)$`) in a copy
  outside the repository, the gate passes, and a real `fork` or `vfork`
  import still fails it. The script is not changed on this branch; anchoring
  it is a gate change for the owner to approve.
