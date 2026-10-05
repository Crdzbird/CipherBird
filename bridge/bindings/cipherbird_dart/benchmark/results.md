| Operation | cipherbird (native) | pointycastle | cryptography | crypto |
|---|---|---|---|---|
| SHA-256, 1 MiB | 282 MB/s | 80 MB/s (3.5x slower) | 96 MB/s (2.9x slower) | 98 MB/s (2.9x slower) |
| BLAKE2b-512, 1 MiB | 671 MB/s | 31 MB/s (21.7x slower) | n/a | n/a |
| BLAKE3, 1 MiB | 1347 MB/s | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 299 MB/s | 46 MB/s (6.5x slower) | 26 MB/s (11.5x slower) | n/a |
| AES-256-GCM encrypt, 1 MiB | 736 MB/s | 1 MB/s (659.2x slower) | 14 MB/s (53.2x slower) | n/a |
| Ed25519 sign, 1 KiB | 42531 ops/s | n/a | 377 ops/s (112.7x slower) | n/a |
| Ed25519 verify, 1 KiB | 18697 ops/s | n/a | 375 ops/s (49.8x slower) | n/a |
| X25519 shared secret | 22822 ops/s | n/a | 1387 ops/s (16.5x slower) | n/a |
| Argon2id, 64 MiB, 2 passes | 13.7 ops/s | 1.7 ops/s (8.0x slower) | 2.4 ops/s (5.8x slower) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 12061 ops/s | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 3839 ops/s | n/a | n/a | n/a |

In Chrome 155 (dart2js), against the WebAssembly engine; `cryptography` uses the browser's Web Crypto API where available:

| Operation | cipherbird (WebAssembly) | pointycastle | cryptography | crypto |
|---|---|---|---|---|
| SHA-256, 1 MiB | 102 MB/s | 2 MB/s (51.0x slower) | 1498 MB/s (14.7x faster) | 121 MB/s (1.2x faster) |
| BLAKE2b-512, 1 MiB | 133 MB/s | 2 MB/s (66.5x slower) | n/a | n/a |
| BLAKE3, 1 MiB | 131 MB/s | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 103 MB/s | error: PlatformException | 34 MB/s (3.0x slower) | n/a |
| AES-256-GCM encrypt, 1 MiB | 51 MB/s | 1 MB/s (51.0x slower) | 1806 MB/s (35.4x faster) | n/a |
| Ed25519 sign, 1 KiB | 18192 ops/s | n/a | 13072 ops/s (1.4x slower) | n/a |
| Ed25519 verify, 1 KiB | 8528 ops/s | n/a | 16640 ops/s (2.0x faster) | n/a |
| X25519 shared secret | 10283 ops/s | n/a | 10520 ops/s (1.0x faster) | n/a |
| Argon2id, 64 MiB, 2 passes | 11.8 ops/s | 0.1 ops/s (118.0x slower) | 0.3 ops/s (39.3x slower) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 5865 ops/s | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 1858 ops/s | n/a | n/a | n/a |
