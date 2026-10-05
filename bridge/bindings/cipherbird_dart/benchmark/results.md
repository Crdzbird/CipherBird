| Operation | cipherbird (native) | pointycastle | cryptography | crypto |
|---|---|---|---|---|
| SHA-256, 1 MiB | 275 MB/s | 76 MB/s (3.6x slower) | 90 MB/s (3.1x slower) | 90 MB/s (3.0x slower) |
| BLAKE2b-512, 1 MiB | 624 MB/s | 29 MB/s (21.3x slower) | n/a | n/a |
| BLAKE3, 1 MiB | 1278 MB/s | n/a | n/a | n/a |
| XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB | 273 MB/s | 46 MB/s (5.9x slower) | 26 MB/s (10.5x slower) | n/a |
| AES-256-GCM encrypt, 1 MiB | 647 MB/s | 1 MB/s (584.4x slower) | 14 MB/s (47.7x slower) | n/a |
| Ed25519 sign, 1 KiB | 42771 ops/s | n/a | 415 ops/s (103.2x slower) | n/a |
| Ed25519 verify, 1 KiB | 20353 ops/s | n/a | 403 ops/s (50.5x slower) | n/a |
| X25519 shared secret | 24581 ops/s | n/a | 1494 ops/s (16.5x slower) | n/a |
| Argon2id, 64 MiB, 2 passes | 15.2 ops/s | 1.8 ops/s (8.3x slower) | 2.4 ops/s (6.3x slower) | n/a |
| ML-KEM-768 keygen + encapsulate + decapsulate | 11847 ops/s | n/a | n/a | n/a |
| Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate | 3826 ops/s | n/a | n/a | n/a |
