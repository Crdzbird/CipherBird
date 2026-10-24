Measured on 2026-10-22, Apple M3 Max, macOS 26.6, Dart 3.13.5, with another process using about three cores; see the README for the conditions.

| Operation | cipherbird (native) | vs 1.1.0 engine | pointycastle | cryptography | crypto |
|---|---|---|---|---|---|
| SHA-256, 1 MiB | 217 MB/s, 4.60 ms | -7% | 74 MB/s, 13.5 ms (2.9x slower, +8.87 ms) | 90 MB/s, 11.1 ms (2.4x slower, +6.49 ms) | 91 MB/s, 11.0 ms (2.4x slower, +6.40 ms) |
| BLAKE2b-512, 1 MiB | 514 MB/s, 1.94 ms | +23% | 31 MB/s, 32.1 ms (16.5x slower, +30.2 ms) | n/a | n/a |
| BLAKE3, 1 MiB | 820 MB/s, 1.22 ms | +3% | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 296 MB/s, 3.38 ms | +14% | 46 MB/s, 21.6 ms (6.4x slower, +18.2 ms) | 26 MB/s, 38.5 ms (11.4x slower, +35.1 ms) | n/a |
| AES-256-GCM encrypt, 1 MiB | 651 MB/s, 1.54 ms | +17% | 1 MB/s, 901.5 ms (586.7x slower, +900.0 ms) | 14 MB/s, 71.9 ms (46.8x slower, +70.3 ms) | n/a |
| Ed25519 sign, 1 KiB | 49597 ops/s, 20.2 us | +20% | n/a | 424 ops/s, 2.36 ms (116.9x slower, +2.34 ms) | n/a |
| Ed25519 verify, 1 KiB | 21576 ops/s, 46.3 us | +8% | n/a | 421 ops/s, 2.37 ms (51.2x slower, +2.33 ms) | n/a |
| X25519 shared secret | 25549 ops/s, 39.1 us | +6% | n/a | 1501 ops/s, 666.1 us (17.0x slower, +627.0 us) | n/a |
| Argon2id, 64 MiB, 2 passes | 14.1 ops/s, 70.7 ms | -3% | 1.8 ops/s, 563.8 ms (8.0x slower, +493.2 ms) | 2.6 ops/s, 386.4 ms (5.5x slower, +315.7 ms) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 14079 ops/s, 71.0 us | +9% | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 4272 ops/s, 234.1 us | +10% | n/a | n/a | n/a |
| ML-DSA-65 sign, 1 KiB | 2308 ops/s, 433.2 us | new | n/a | n/a | n/a |
| ML-DSA-65 verify, 1 KiB | 9407 ops/s, 106.3 us | new | n/a | n/a | n/a |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 1614 ops/s, 619.5 us | new | n/a | n/a | n/a |
| X-Wing keygen + encapsulate + decapsulate | 4425 ops/s, 226.0 us | new | n/a | n/a | n/a |
| HPKE X-Wing seal + open, 1 KiB | 4309 ops/s, 232.1 us | new | n/a | n/a | n/a |
| Suite v2 seal + open, 1 KiB | 1129 ops/s, 885.6 us | new | n/a | n/a | n/a |
| Session v2 handshake (prekey, initiate, accept) | 573 ops/s, 1.75 ms | new | n/a | n/a | n/a |
| Session v2 message encrypt + decrypt, 1 KiB | 11485 ops/s, 87.1 us | new | n/a | n/a | n/a |

| Operation | cipherbird (native) | fastest alternative | time per operation | difference |
|---|---|---|---|---|
| SHA-256, 1 MiB | 4.60 ms | crypto | 11.0 ms | +6.40 ms |
| BLAKE2b-512, 1 MiB | 1.94 ms | pointycastle | 32.1 ms | +30.2 ms |
| BLAKE3, 1 MiB | 1.22 ms | none | | |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 3.38 ms | pointycastle | 21.6 ms | +18.2 ms |
| AES-256-GCM encrypt, 1 MiB | 1.54 ms | cryptography | 71.9 ms | +70.3 ms |
| Ed25519 sign, 1 KiB | 20.2 us | cryptography | 2.36 ms | +2.34 ms |
| Ed25519 verify, 1 KiB | 46.3 us | cryptography | 2.37 ms | +2.33 ms |
| X25519 shared secret | 39.1 us | cryptography | 666.1 us | +627.0 us |
| Argon2id, 64 MiB, 2 passes | 70.7 ms | cryptography | 386.4 ms | +315.7 ms |
| ML-KEM-768 keygen + encapsulate + decapsulate | 71.0 us | none | | |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 234.1 us | none | | |
| ML-DSA-65 sign, 1 KiB | 433.2 us | none | | |
| ML-DSA-65 verify, 1 KiB | 106.3 us | none | | |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 619.5 us | none | | |
| X-Wing keygen + encapsulate + decapsulate | 226.0 us | none | | |
| HPKE X-Wing seal + open, 1 KiB | 232.1 us | none | | |
| Suite v2 seal + open, 1 KiB | 885.6 us | none | | |
| Session v2 handshake (prekey, initiate, accept) | 1.75 ms | none | | |
| Session v2 message encrypt + decrypt, 1 KiB | 87.1 us | none | | |

In Chrome 155 (dart2js), against the WebAssembly engine; `cryptography` uses the browser's Web Crypto API where available:

| Operation | cipherbird (WebAssembly) | vs 1.1.0 published | pointycastle | cryptography | crypto |
|---|---|---|---|---|---|
| SHA-256, 1 MiB | 63 MB/s, 15.8 ms | -38% | 2 MB/s, 605.0 ms (38.3x slower, +589.2 ms) | 1452 MB/s, 688.7 us (23.0x faster, -15.1 ms) | 118 MB/s, 8.45 ms (1.9x faster, -7.36 ms) |
| BLAKE2b-512, 1 MiB | 73 MB/s, 13.7 ms | -45% | 2 MB/s, 408.5 ms (29.8x slower, +394.8 ms) | n/a | n/a |
| BLAKE3, 1 MiB | 72 MB/s, 13.9 ms | -45% | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 63 MB/s, 15.8 ms | -39% | error: PlatformException | 36 MB/s, 27.6 ms (1.7x slower, +11.7 ms) | n/a |
| AES-256-GCM encrypt, 1 MiB | 39 MB/s, 25.8 ms | -24% | 1 MB/s, 1.56 s (60.6x slower, +1.54 s) | 1708 MB/s, 585.5 us (44.0x faster, -25.2 ms) | n/a |
| Ed25519 sign, 1 KiB | 15914 ops/s, 62.8 us | -13% | n/a | 13137 ops/s, 76.1 us (1.2x slower, +13.3 us) | n/a |
| Ed25519 verify, 1 KiB | 7993 ops/s, 125.1 us | -6% | n/a | 16631 ops/s, 60.1 us (2.1x faster, -65.0 us) | n/a |
| X25519 shared secret | 10129 ops/s, 98.7 us | -1% | n/a | 10532 ops/s, 95.0 us (1.0x faster, -3.77 us) | n/a |
| Argon2id, 64 MiB, 2 passes | 11.9 ops/s, 84.3 ms | +1% | 0.1 ops/s, 18.83 s (223.4x slower, +18.75 s) | 0.3 ops/s, 3.56 s (42.2x slower, +3.47 s) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 4913 ops/s, 203.6 us | -16% | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 1946 ops/s, 513.9 us | +5% | n/a | n/a | n/a |
| ML-DSA-65 sign, 1 KiB | 2116 ops/s, 472.7 us | new | n/a | n/a | n/a |
| ML-DSA-65 verify, 1 KiB | 5104 ops/s, 195.9 us | new | n/a | n/a | n/a |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 1293 ops/s, 773.5 us | new | n/a | n/a | n/a |
| X-Wing keygen + encapsulate + decapsulate | 2150 ops/s, 465.1 us | new | n/a | n/a | n/a |
| HPKE X-Wing seal + open, 1 KiB | 1993 ops/s, 501.8 us | new | n/a | n/a | n/a |
| Suite v2 seal + open, 1 KiB | 807 ops/s, 1.24 ms | new | n/a | n/a | n/a |
| Session v2 handshake (prekey, initiate, accept) | 391 ops/s, 2.56 ms | new | n/a | n/a | n/a |
| Session v2 message encrypt + decrypt, 1 KiB | 7651 ops/s, 130.7 us | new | n/a | n/a | n/a |

| Operation | cipherbird (WebAssembly) | fastest alternative | time per operation | difference |
|---|---|---|---|---|
| SHA-256, 1 MiB | 15.8 ms | cryptography | 688.7 us | -15.1 ms |
| BLAKE2b-512, 1 MiB | 13.7 ms | pointycastle | 408.5 ms | +394.8 ms |
| BLAKE3, 1 MiB | 13.9 ms | none | | |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 15.8 ms | cryptography | 27.6 ms | +11.7 ms |
| AES-256-GCM encrypt, 1 MiB | 25.8 ms | cryptography | 585.5 us | -25.2 ms |
| Ed25519 sign, 1 KiB | 62.8 us | cryptography | 76.1 us | +13.3 us |
| Ed25519 verify, 1 KiB | 125.1 us | cryptography | 60.1 us | -65.0 us |
| X25519 shared secret | 98.7 us | cryptography | 95.0 us | -3.77 us |
| Argon2id, 64 MiB, 2 passes | 84.3 ms | cryptography | 3.56 s | +3.47 s |
| ML-KEM-768 keygen + encapsulate + decapsulate | 203.6 us | none | | |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 513.9 us | none | | |
| ML-DSA-65 sign, 1 KiB | 472.7 us | none | | |
| ML-DSA-65 verify, 1 KiB | 195.9 us | none | | |
| Hybrid Ed25519 + ML-DSA-65 sign + verify, 1 KiB | 773.5 us | none | | |
| X-Wing keygen + encapsulate + decapsulate | 465.1 us | none | | |
| HPKE X-Wing seal + open, 1 KiB | 501.8 us | none | | |
| Suite v2 seal + open, 1 KiB | 1.24 ms | none | | |
| Session v2 handshake (prekey, initiate, accept) | 2.56 ms | none | | |
| Session v2 message encrypt + decrypt, 1 KiB | 130.7 us | none | | |

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
