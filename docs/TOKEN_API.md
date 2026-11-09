# Tokens: one API for every format

Status: design note, 2026-11-09, implemented the same day in the engine
(`include/cryptolib/token.hpp`, the eight `cryptolib_token_*` functions)
and in the Go, Dart and Node bindings. Supersedes the per-format API
section of `CB1_TOKEN.md`; the per-format functions stay as aliases.

## The problem

Every token format has so far arrived as its own family of entry points:
`cryptolib_paseto_v4_local_encrypt` and `_decrypt` for PASETO v4.local,
`cryptolib_cb1_local_encrypt`, `_decrypt`, `cryptolib_cb1_public_sign` and
`_verify` for cb1, each with its `_len` or `_cap` helper, each wrapped by
hand in Go, both Dart packages and Node, each with a parity-test entry, a
README row and a changelog line. The next format (cb2, or PASETO v4.public,
or a v5) would repeat all of it, across every binding, before anyone can
use it, and the bindings would need a coordinated release for code that is
the same four calls with another name.

The families differ in nothing but the format. Encrypt and sign take the
key, the payload, a footer and an implicit assertion and return the token
text; decrypt and verify take the token, the key, the expected footer and
the implicit assertion and return the payload. The return codes are shared
already. So the format becomes an argument and the API stops growing.

## The contract

### Formats

A format is named by its token header without the trailing dot: `v4.local`,
`cb1.local`, `cb1.public`, later `cb2.local`, `cb2.public`, `v4.public` and
whatever else the engine learns. The name is ASCII, NUL-terminated across
the C ABI, and compared exactly.

The suffix fixes the purpose. A `.local` format is symmetric: issue
encrypts under a shared key and accept decrypts under the same key. A
`.public` format is asymmetric: issue signs with the secret half of a pair
and accept verifies with the public half and returns the payload. A format
with any other suffix is refused.

The engine publishes its table:

```c
size_t cryptolib_token_formats(char* out, size_t out_cap);
```

It writes a JSON array to `out` and returns the number of bytes the full
text needs, so a call with `out_cap` 0 sizes the buffer. Each element:

```json
{"format": "cb1.public", "purpose": "public", "standard": "library-native",
 "key_bytes": 0, "public_key_bytes": 1984, "secret_key_bytes": 4096,
 "signature_bytes": 3373, "max_input_bytes": 67108864, "available": true}
```

`key_bytes` is the shared key length of a local format and 0 for a public
one; the two pair sizes and the signature size are 0 for a local format.
`standard` is `PASETO v4` for a published specification the engine follows
byte for byte and `library-native` for CipherBird's own. `available` is
false where the format is compiled out or policy-blocked in this profile
(cb1 in the bank profile, everything in the fips profile): the entry stays
in the list so a client can say why a call reports unavailable. The order
of the array is stable within a release and carries no meaning.

### Sizing

```c
size_t cryptolib_token_issue_len(const char* format, size_t payload_len, size_t footer_len);
size_t cryptolib_token_accept_cap(const char* format, size_t token_len);
```

The exact token length a format produces for a payload and footer, and the
output capacity accept needs for a token of a given length. Both return 0
for an unknown format and for lengths beyond the format's maximum, as the
per-format helpers do today.

### Keys

```c
int cryptolib_token_keygen(const char* format,
                           uint8_t* secret, size_t secret_cap, size_t* secret_len,
                           uint8_t* pub, size_t pub_cap, size_t* pub_len);
```

For a local format it writes `key_bytes` of CSPRNG output to `secret` and
sets `*pub_len` to 0 (`pub` may be NULL with a zero capacity). For a public
format it writes the pair. Capacities come from the table.

Keys stay raw bytes, as every binding already holds them. The table gives
each format exact sizes, so a public key cannot pass for a secret key or a
shared key, and the remaining confusion, a 32-byte key handed to the wrong
local format, fails authentication because every format binds its own
header into the tag through PAE. Self-describing key strings (PASERK for
PASETO, the kcb2 strings of cb2, a kcb1 form for cb1) would add key ids and
a type check in the string itself; they are a separate layer on top of this
one and not a precondition for it.

### Issue and accept

```c
int cryptolib_token_issue(const char* format,
                          uint8_t* out, size_t out_cap, size_t* out_len,
                          const uint8_t* key, size_t key_len,
                          const uint8_t* payload, size_t payload_len,
                          const uint8_t* footer, size_t footer_len,
                          const uint8_t* implicit, size_t implicit_len);

int cryptolib_token_accept(const char* format,
                           uint8_t* out, size_t out_cap, size_t* out_len,
                           const uint8_t* token, size_t token_len,
                           const uint8_t* key, size_t key_len,
                           const uint8_t* expected_footer, size_t expected_footer_len,
                           const uint8_t* implicit, size_t implicit_len);
```

Issue encrypts (local) or signs (public, `key` is the secret half) and
writes the token text, ASCII and not NUL-terminated. Accept decrypts or
verifies (public, `key` is the public half) and writes the payload. The
argument rules are the ones of the v4.local functions: NULL is allowed only
with a zero length, inputs are capped by the format's maximum, `out` may
overlap no input, an empty footer is omitted from the token, the implicit
assertion is authenticated and never stored, `*out_len` is 0 on any
failure, derived keys live on the stack and are wiped.

The caller always names the format it expects. Accept reads the token's
header, compares it with `format` and rejects a mismatch as invalid before
touching the key. The header inside the token never chooses the algorithm;
that is the confusion PASETO was designed to make impossible, and a generic
entry point must not reintroduce it. A verifier that accepts several
formats during a rotation reads the header first (below), checks it against
its own allow-list, and then calls accept with the format it chose.

### Reading before verifying

```c
size_t cryptolib_token_peek_format(const uint8_t* token, size_t token_len,
                                   char* out, size_t out_cap);
int cryptolib_token_peek_footer(const uint8_t* token, size_t token_len,
                                uint8_t* out, size_t out_cap, size_t* out_len);
```

The first writes the header of the token as a format name and returns the
length it needs, or 0 when the text has no header of the known shape. The
second decodes the footer, the usual place for a key id, so a verifier can
pick a key. Both are unverified by definition: nothing they return is to be
trusted until accept succeeds with the key the footer named, and the footer
accept compares is the caller's `expected_footer`, not the one it just
read. The documentation of every binding says so next to the call.

### Return codes

The values stay those of the PASETO functions, under format-neutral names;
the old names remain as aliases.

| Name | Value | Meaning |
|---|---|---|
| `CRYPTOLIB_TOKEN_OK` | 0 | success |
| `CRYPTOLIB_TOKEN_ERR_INVALID` | -1 | the token is not accepted, with no further detail: wrong header, bad base64url, wrong length, failed tag or signature, footer mismatch |
| `CRYPTOLIB_TOKEN_ERR_ARGUMENT` | -2 | a caller error: a key of the wrong length, a NULL with a non-zero length, an input over the maximum, an output buffer too small |
| `CRYPTOLIB_TOKEN_ERR_INTERNAL` | -3 | the engine failed (no randomness, a backend error) |
| `CRYPTOLIB_TOKEN_ERR_UNAVAILABLE` | -4 | the format exists but is not available in this profile |
| `CRYPTOLIB_TOKEN_ERR_FORMAT` | -5 | the format string names no format this engine knows |

Invalid stays one code on purpose: a verifier that distinguished a bad tag
from a bad footer or a wrong header would be an oracle. Argument errors are
the caller's own inputs and carry no secret. Format and unavailable are
distinguished from argument so a binding can raise a message a developer
can act on ("cb1 is not in the bank profile") without the engine knowing
anything about the token.

## Engine design

`include/cryptolib/token.hpp` holds a descriptor per format and a table:

```cpp
struct Format {
    std::string_view name;        /* "cb1.local" */
    Purpose purpose;              /* local or public */
    std::string_view standard;
    std::size_t key_bytes, public_key_bytes, secret_key_bytes, signature_bytes;
    std::size_t max_input_bytes;
    bool (*available)();
    std::size_t (*issue_len)(std::size_t, std::size_t);
    std::size_t (*accept_cap)(std::size_t);
    int (*keygen)(...);
    int (*issue)(...);
    int (*accept)(...);
};
inline constexpr Format FORMATS[] = { v4_local, cb1_local, cb1_public };
```

The generic C ABI functions look the format up by name and call through.
The per-format C ABI functions of 1.4.0 become one-line calls into the same
table, so there is one code path and the existing vectors keep testing it.
Adding a format is one implementation header, one table entry, one vector
file and nothing else: no new symbol, no binding change, no parity-test
line. In a profile where a format is compiled out, its entry carries
`available` false and stubs that return unavailable, which is how the bank
profile treats cb1 today.

## Bindings

Each binding that wraps the token functions (Go, the two Dart packages,
Node) exposes the generic surface and keeps the 1.4.0 names:

| | Dart | Node | Go |
|---|---|---|---|
| table | `lib.tokenFormats()`, `lib.tokens.formats()` | `tokenFormats()`, `Tokens.formats()` | `TokenFormats()` |
| keys | `lib.tokenKeygen(format)` | `tokenKeygen(format)` | `TokenKeygen(format)` |
| issue | `lib.tokenIssue(format, key, payload, footer:, implicit:)` | `tokenIssue(format, key, payload, footer, implicit)` | `TokenIssue(format, key, payload, footer, implicit)` |
| accept | `lib.tokenAccept(format, token, key, expectedFooter:, implicit:)` | `tokenAccept(format, token, key, expectedFooter, implicit)` | `TokenAccept(format, token, key, expectedFooter, implicit)`, `TokenAcceptTo` |
| peek | `lib.tokenPeekFormat(token)`, `lib.tokenPeekFooter(token)` | `tokenPeekFormat`, `tokenPeekFooter` | `TokenPeekFormat`, `TokenPeekFooter` |

In Dart the six also live on `lib.tokens` (`formats`, `keygen`, `issue`,
`accept`, `peekFormat`, `peekFooter`), with `TokenFormat` and `TokenKeys` as
the value types; in Node on `Tokens` and the `tokens` namespace. The 1.4.0
names stay as they are in this release, documented as the generic calls with
the format fixed; the deprecation marks follow in the release that ships
the generic API, so current callers see no warnings before the new calls
are available to them.

Keys are the byte types each language already uses; `keygen` returns a
secret and, for a public format, the public half. Errors map to the
existing `TokenStatus` with two new members, `format` and `unavailable`
(where the latter does not exist yet). Nothing in a binding names a
format: the strings pass through, and `formats` is how an application or a
UI learns what the engine it ships with can do.

## Vectors

One schema for every format under `tests/vectors/tokens/<format>.json`:

```json
{"format": "cb1.local", "note": "...",
 "cases": [{"name": "cb1-L-1", "expect-fail": false,
            "key": "<hex>", "nonce": "<hex, local only, optional>",
            "token": "...", "payload": "...", "footer": "", "implicit-assertion": ""}]}
```

Public formats carry `public-key` and `secret-key` instead of `key`. The
existing cb1 vectors already have these fields; `scripts/tokens/convert_vectors.py`
writes them, and the v4.local cases of the official PASETO vectors, into
the common files. The official PASETO file stays as published, and the C++
suite keeps reading it in its own schema as well. Every binding gets one test
loop: for each file, for each case, accept with the file's format and
compare the payload or expect the failure. A format arrives with its vector
file and is tested everywhere by that loop. The C++ suite additionally
re-issues local cases under the pinned nonce and compares byte for byte.

## What a new format costs after this

In the engine: the construction, its table entry, its vectors, a line in
the format's own document. In the packages: nothing in code. The engine
build still has to reach them, because every package bundles the engine,
so a release is a run of the Engines workflow, the import script that
places the attested slices in the Flutter plugin, the Dart twin and the npm
prebuild, a version bump and a changelog line. That is the procedure used
for 1.4.0 with the wrapper work removed; it can be a single script. Moving
the engine into its own package so that the language packages need no
release at all is possible but is a packaging change with its own trade-offs
(version pinning between the two, the web integrity digest) and is not
needed for this.

## Later, on the same contract

- Claims and rules. Accept returns the payload bytes; applications parse
  claims themselves today. An `accept_claims` call that takes a JSON rules
  string (`{"iss": "...", "aud": "...", "skew": 60, "now": 1700000000,
  "require_exp": true}`) would validate exp, nbf, iat, iss, aud, sub and
  jti in the engine and return the claims, with the richer statuses cb2
  uses (expired, not yet valid, issuer mismatch and so on) from -16
  downward so the codes above stay free. A new rule is a new JSON field,
  not a new parameter in four languages.
- Self-describing keys, as above, once the formats agree on a string
  grammar; PASERK and kcb2 are the models.

## Rollout

1. This note.
2. Engine: `token.hpp`, the eight generic C ABI functions, the per-format
   functions rewritten over the table, the vector loop in the C++ suite,
   the bank and fips profiles reporting unavailable through the table.
3. Go, Dart (both packages from the one source tree) and Node: the generic
   surface, the forwarders, the vector loop, the parity tests.
4. Release 1.5.0 with the 1.4.0 names deprecated; remove them in 2.0.
