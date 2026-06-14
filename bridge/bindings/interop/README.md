# Go ↔ Flutter/Dart interop example

A value encrypted by the **Go** binding decrypts cleanly in the **Flutter/Dart**
binding, and vice-versa — because both are thin wrappers over the *same* native
`libcryptolib_c`. The ciphertext format is the library's format, not a
per-language one.

This example demonstrates **all three directions** with authenticated
public-key encryption (Box / X25519, the NaCl `crypto_box` construction):

1. **Go ──▶ Flutter** — Go encrypts, Dart decrypts.
2. **Flutter ──▶ Go** — Dart encrypts, Go decrypts.
3. **Flutter ◀──▶ Go** — a two-way ping/pong conversation.

Plus a negative control: a tampered ciphertext is rejected (AEAD authentication).

> The Dart party uses `package:cryptolib_dart` — the **exact** `dart:ffi` binding
> the Flutter plugin ships — so its behaviour is identical to a real Flutter app.

## Run it

```sh
# 1. Build the native library once.
cmake -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release --target cryptolib_c

# 2. Run the demo (needs the Go toolchain and the Dart SDK).
bridge/bindings/interop/run.sh
```

Expected tail:

```
  ✓ Flutter decrypted Go's message
  ✓ Go decrypted Flutter's message
  ✓ Flutter received Go's ping
  ✓ Go received Flutter's pong
  ✓ tampered ciphertext rejected by Flutter (authentication held)
  INTEROP RESULT: 5 passed, 0 failed
```

## How it fits together

| Piece | Path | Role |
| --- | --- | --- |
| Go party    | [`bridge/bindings/go/interop/main.go`](../go/interop/main.go) | `keygen` / `enc` / `dec` CLI over the Go binding |
| Dart party  | [`bridge/bindings/dart/bin/interop_party.dart`](../dart/bin/interop_party.dart) | same CLI over the Flutter/Dart binding |
| Orchestrator| [`run.sh`](run.sh) | exchanges public keys, runs all three directions, verifies |

Both parties expose the same tiny protocol:

```
keygen                                    -> "<pubHex> <secHex>"
enc <recipientPubHex> <senderSecHex> <msg> -> "<ciphertextHex>"
dec <senderPubHex> <recipientSecHex> <ct>  -> the decrypted UTF-8 text
```

## The model (and how to adapt it)

Box is **authenticated**: each side has an X25519 keypair, the two public keys
are exchanged once, and from then on either side can send a message the other
both decrypts *and* verifies came from the expected peer.

- **Encrypt** with the *recipient's public key* and *your own secret key*.
- **Decrypt** with the *sender's public key* and *your own secret key*.
- The 24-byte nonce is generated and prepended automatically — you never manage
  it. Output is `nonce ‖ ciphertext ‖ 16-byte tag`.

### Transport

The ciphertext is raw bytes (`[]byte` in Go, `Uint8List` in Dart — the same
bytes). To move it over a text channel (JSON/HTTP), **base64- or hex-encode it**
and decode identically on the other side. This demo uses hex on the command
line for exactly that reason.

### Want a simpler shared-key version?

If both sides already share a 32-byte symmetric key, swap Box for symmetric
AEAD — `XChaCha20Encrypt(plaintext, key, aad)` in Go and
`xchacha20Decrypt(ct, key, aad)` in Dart. Same rule: share the key out-of-band,
keep the AAD identical on both ends.

### Production notes

- This demo generates fresh keypairs each run. In a real app, persist each
  side's keypair and distribute public keys through your normal channel.
- For long-term confidentiality against future quantum attackers, use the
  hybrid KEM (`HybridKemKeygen` / `hybridKemKeygen`) to agree a shared secret,
  then symmetric AEAD — the same cross-binding portability applies.
