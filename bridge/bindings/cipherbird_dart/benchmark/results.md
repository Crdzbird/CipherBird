Measured on 2026-10-24, Apple M3 Max, macOS 26.6.2, Dart 3.13.5. Another
process (a scoring script with four workers) used about two cores at the
start of the session and one at the end; see the README for the conditions.
The "vs 1.1.0 engine" column is the 1.1.0 engine measured back to back in
the same session, so it reflects the engine and not the machine.

| Operation | cipherbird (native) | vs 1.1.0 engine | pointycastle | cryptography | crypto |
|---|---|---|---|---|---|
| SHA-256, 1 MiB | 232 MB/s, 4.30 ms | -5% | 81 MB/s, 12.3 ms (2.9x slower, +7.99 ms) | 96 MB/s, 10.4 ms (2.4x slower, +6.07 ms) | 98 MB/s, 10.2 ms (2.4x slower, +5.87 ms) |
| BLAKE2b-512, 1 MiB | 543 MB/s, 1.84 ms | +14% | 31 MB/s, 32.4 ms (17.6x slower, +30.6 ms) | n/a | n/a |
| BLAKE3, 1 MiB | 833 MB/s, 1.20 ms | +2% | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 304 MB/s, 3.29 ms | +13% | 47 MB/s, 21.5 ms (6.5x slower, +18.2 ms) | 26 MB/s, 38.4 ms (11.7x slower, +35.1 ms) | n/a |
| AES-256-GCM encrypt, 1 MiB | 672 MB/s, 1.49 ms | +17% | 1 MB/s, 899.3 ms (604.4x slower, +897.8 ms) | 14 MB/s, 72.9 ms (49.0x slower, +71.5 ms) | n/a |
| Ed25519 sign, 1 KiB | 49862 ops/s, 20.1 us | +18% | n/a | 417 ops/s, 2.40 ms (119.6x slower, +2.38 ms) | n/a |
| Ed25519 verify, 1 KiB | 21981 ops/s, 45.5 us | +10% | n/a | 413 ops/s, 2.42 ms (53.2x slower, +2.37 ms) | n/a |
| X25519 shared secret | 26221 ops/s, 38.1 us | +6% | n/a | 1505 ops/s, 664.5 us (17.4x slower, +626.4 us) | n/a |
| Argon2id, 64 MiB, 2 passes | 14.3 ops/s, 70.0 ms | -8% | 1.9 ops/s, 537.6 ms (7.7x slower, +467.6 ms) | 2.6 ops/s, 386.1 ms (5.5x slower, +316.1 ms) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 14570 ops/s, 68.6 us | +12% | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 4632 ops/s, 215.9 us | +10% | n/a | n/a | n/a |
| ML-DSA-65 sign, 1 KiB | 2538 ops/s, 393.9 us | new | n/a | n/a | n/a |
| ML-DSA-65 verify, 1 KiB | 10117 ops/s, 98.8 us | new | n/a | n/a | n/a |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 1759 ops/s, 568.6 us | new | n/a | n/a | n/a |
| X-Wing keygen + encapsulate + decapsulate | 4938 ops/s, 202.5 us | new | n/a | n/a | n/a |
| HPKE X-Wing seal + open, 1 KiB | 4714 ops/s, 212.1 us | new | n/a | n/a | n/a |
| Suite v2 seal + open, 1 KiB | 1220 ops/s, 819.9 us | new | n/a | n/a | n/a |
| Session v2 handshake (prekey, initiate, accept) | 618 ops/s, 1.62 ms | new | n/a | n/a | n/a |
| Session v2 message encrypt + decrypt, 1 KiB | 13142 ops/s, 76.1 us | new | n/a | n/a | n/a |

| Operation | cipherbird (native) | fastest alternative | time per operation | difference |
|---|---|---|---|---|
| SHA-256, 1 MiB | 4.30 ms | crypto | 10.2 ms | +5.87 ms |
| BLAKE2b-512, 1 MiB | 1.84 ms | pointycastle | 32.4 ms | +30.6 ms |
| BLAKE3, 1 MiB | 1.20 ms | none | | |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 3.29 ms | pointycastle | 21.5 ms | +18.2 ms |
| AES-256-GCM encrypt, 1 MiB | 1.49 ms | cryptography | 72.9 ms | +71.5 ms |
| Ed25519 sign, 1 KiB | 20.1 us | cryptography | 2.40 ms | +2.38 ms |
| Ed25519 verify, 1 KiB | 45.5 us | cryptography | 2.42 ms | +2.37 ms |
| X25519 shared secret | 38.1 us | cryptography | 664.5 us | +626.4 us |
| Argon2id, 64 MiB, 2 passes | 70.0 ms | cryptography | 386.1 ms | +316.1 ms |
| ML-KEM-768 keygen + encapsulate + decapsulate | 68.6 us | none | | |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 215.9 us | none | | |
| ML-DSA-65 sign, 1 KiB | 393.9 us | none | | |
| ML-DSA-65 verify, 1 KiB | 98.8 us | none | | |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 568.6 us | none | | |
| X-Wing keygen + encapsulate + decapsulate | 202.5 us | none | | |
| HPKE X-Wing seal + open, 1 KiB | 212.1 us | none | | |
| Suite v2 seal + open, 1 KiB | 819.9 us | none | | |
| Session v2 handshake (prekey, initiate, accept) | 1.62 ms | none | | |
| Session v2 message encrypt + decrypt, 1 KiB | 76.1 us | none | | |

In Chrome 155 (dart2js), against the 2.99 MB SIMD WebAssembly engine;
`cryptography` uses the browser's Web Crypto API where available. The
browser cannot swap engines in one session, so its change column compares
against the figures published for 1.1.0.

| Operation | cipherbird (WebAssembly) | vs 1.1.0 | pointycastle | cryptography | crypto |
|---|---|---|---|---|---|
| SHA-256, 1 MiB | 67 MB/s, 14.8 ms | -34% | 2 MB/s, 570.6 ms (38.4x slower, +555.8 ms) | 1560 MB/s, 641.2 us (23.2x faster, -14.2 ms) | 124 MB/s, 8.05 ms (1.8x faster, -6.79 ms) |
| BLAKE2b-512, 1 MiB | 76 MB/s, 13.1 ms | -43% | 3 MB/s, 383.0 ms (29.3x slower, +369.9 ms) | n/a | n/a |
| BLAKE3, 1 MiB | 77 MB/s, 13.0 ms | -41% | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 67 MB/s, 14.8 ms | -35% | error: PlatformException | 28 MB/s, 35.5 ms (2.4x slower, +20.7 ms) | n/a |
| AES-256-GCM encrypt, 1 MiB | 40 MB/s, 24.7 ms | -21% | 1 MB/s, 1.48 s (60.0x slower, +1.46 s) | 1911 MB/s, 523.4 us (47.2x faster, -24.2 ms) | n/a |
| Ed25519 sign, 1 KiB | 17980 ops/s, 55.6 us | -1% | n/a | 14106 ops/s, 70.9 us (1.3x slower, +15.3 us) | n/a |
| Ed25519 verify, 1 KiB | 8684 ops/s, 115.2 us | +2% | n/a | 17885 ops/s, 55.9 us (2.1x faster, -59.2 us) | n/a |
| X25519 shared secret | 11396 ops/s, 87.8 us | +11% | n/a | 11243 ops/s, 88.9 us (1.0x slower, +1.19 us) | n/a |
| Argon2id, 64 MiB, 2 passes | 20.3 ops/s, 49.3 ms | +72% | 0.1 ops/s, 17.88 s (362.4x slower, +17.83 s) | 0.3 ops/s, 3.47 s (70.4x slower, +3.42 s) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 5939 ops/s, 168.4 us | +1% | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 2204 ops/s, 453.8 us | +19% | n/a | n/a | n/a |
| ML-DSA-65 sign, 1 KiB | 2368 ops/s, 422.3 us | new | n/a | n/a | n/a |
| ML-DSA-65 verify, 1 KiB | 5617 ops/s, 178.0 us | new | n/a | n/a | n/a |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 1363 ops/s, 733.8 us | new | n/a | n/a | n/a |
| X-Wing keygen + encapsulate + decapsulate | 2303 ops/s, 434.3 us | new | n/a | n/a | n/a |
| HPKE X-Wing seal + open, 1 KiB | 2153 ops/s, 464.5 us | new | n/a | n/a | n/a |
| Suite v2 seal + open, 1 KiB | 841 ops/s, 1.19 ms | new | n/a | n/a | n/a |
| Session v2 handshake (prekey, initiate, accept) | 418 ops/s, 2.39 ms | new | n/a | n/a | n/a |
| Session v2 message encrypt + decrypt, 1 KiB | 7692 ops/s, 130.0 us | new | n/a | n/a | n/a |

| Operation | cipherbird (WebAssembly) | fastest alternative | time per operation | difference |
|---|---|---|---|---|
| SHA-256, 1 MiB | 14.8 ms | cryptography | 641.2 us | -14.2 ms |
| BLAKE2b-512, 1 MiB | 13.1 ms | pointycastle | 383.0 ms | +369.9 ms |
| BLAKE3, 1 MiB | 13.0 ms | none | | |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 14.8 ms | cryptography | 35.5 ms | +20.7 ms |
| AES-256-GCM encrypt, 1 MiB | 24.7 ms | cryptography | 523.4 us | -24.2 ms |
| Ed25519 sign, 1 KiB | 55.6 us | cryptography | 70.9 us | +15.3 us |
| Ed25519 verify, 1 KiB | 115.2 us | cryptography | 55.9 us | -59.2 us |
| X25519 shared secret | 87.8 us | cryptography | 88.9 us | +1.19 us |
| Argon2id, 64 MiB, 2 passes | 49.3 ms | cryptography | 3.47 s | +3.42 s |
| ML-KEM-768 keygen + encapsulate + decapsulate | 168.4 us | none | | |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 453.8 us | none | | |
| ML-DSA-65 sign, 1 KiB | 422.3 us | none | | |
| ML-DSA-65 verify, 1 KiB | 178.0 us | none | | |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 733.8 us | none | | |
| X-Wing keygen + encapsulate + decapsulate | 434.3 us | none | | |
| HPKE X-Wing seal + open, 1 KiB | 464.5 us | none | | |
| Suite v2 seal + open, 1 KiB | 1.19 ms | none | | |
| Session v2 handshake (prekey, initiate, accept) | 2.39 ms | none | | |
| Session v2 message encrypt + decrypt, 1 KiB | 130.0 us | none | | |

### WebAssembly SIMD (2026-10-24)

The engine and every dependency are now compiled with `-msimd128`. Measured
in the same Chrome session against the scalar build, 1 MiB inputs:

| Operation | scalar | SIMD | change |
|---|---|---|---|
| SHA-256 | 65 MB/s | 64 MB/s | none |
| BLAKE2b-512 | 76 MB/s | 76 MB/s | none |
| BLAKE3 | 75 MB/s | 73 MB/s | none |
| XChaCha20-Poly1305 | 65 MB/s | 63 MB/s | none |
| AES-256-GCM | 40 MB/s | 40 MB/s | none |
| Argon2id 64 MiB, 2 passes | 83.8 ms | 52.3 ms | 38% less time |
| ML-KEM-768 round trip | 190.7 us | 169.7 us | 11% less time |
| Hybrid X25519 + ML-KEM-768 | 477.4 us | 446.6 us | 6% less time |
| ML-DSA-65 sign | 445.4 us | 434.3 us | 2% less time |

The portable C of the hashes and ciphers has no wasm SIMD paths, so they
do not move; Argon2id and the lattice arithmetic vectorise. The engine
grows from 4.54 MB to 4.78 MB. WebCrypto stays the fast path for bulk
SHA-2 and AES-GCM in the browser (23x and 40x), reached through
`DeviceFips` there.

### WebAssembly engine size (2026-10-24)

| Build | wasm | code section | data section |
|---|---|---|---|
| SIMD, untrimmed dependencies | 4.78 MB | 2.99 MB | 1.77 MB |
| SIMD, OpenSSL trimmed as natively, small secp256k1 tables | 2.99 MB | 2.47 MB | 0.50 MB |

The data section held the default secp256k1 precomputed tables; the
window-12 and 22 KB generator tables the native builds use remove 1.27 MB,
and the OpenSSL trim removes about half a megabyte of code. Performance is
unchanged from the SIMD table above (Argon2id 52.9 ms, ML-KEM-768 169 us,
SHA-256 65 MB/s, AES-256-GCM 39 MB/s). A first attempt that exported the
SIMD flag without an optimisation level built libsodium unoptimised
(Argon2id 997 ms); the build driver now exports both.
A profiling link attributes the remaining code to the engine's own C++
(0.70 MB), OpenSSL (0.49 MB), liboqs (0.25 MB for ML-KEM, ML-DSA, sntrup
and all twelve SLH-DSA sets, which share their code), the Emscripten
runtime (0.24 MB), secp256k1 (0.19 MB), libsodium (0.19 MB), blst and
BLAKE3 (0.05 MB), with 0.85 MB in functions whose names do not match a
library prefix. Splitting the SLH-DSA parameter sets into a second module
would save little and is not planned.
