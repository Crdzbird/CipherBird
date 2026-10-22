/// Reference figures of the 1.1.0 release, operations per second, as
/// published in results.md. Throughput rows are converted from MB/s on
/// 1 MiB inputs, so one operation is one megabyte.
const Map<String, double> previousNative = {
  'SHA-256, 1 MiB': 282,
  'BLAKE2b-512, 1 MiB': 671,
  'BLAKE3, 1 MiB': 1347,
  'XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB': 299,
  'AES-256-GCM encrypt, 1 MiB': 736,
  'Ed25519 sign, 1 KiB': 42531,
  'Ed25519 verify, 1 KiB': 18697,
  'X25519 shared secret': 22822,
  'Argon2id, 64 MiB, 2 passes': 13.7,
  'ML-KEM-768 keygen + encapsulate + decapsulate': 12061,
  'Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate': 3839,
};

/// The same for the WebAssembly engine in Chrome.
const Map<String, double> previousWeb = {
  'SHA-256, 1 MiB': 102,
  'BLAKE2b-512, 1 MiB': 133,
  'BLAKE3, 1 MiB': 131,
  'XChaCha20/ChaCha20-Poly1305 encrypt, 1 MiB': 103,
  'AES-256-GCM encrypt, 1 MiB': 51,
  'Ed25519 sign, 1 KiB': 18192,
  'Ed25519 verify, 1 KiB': 8528,
  'X25519 shared secret': 10283,
  'Argon2id, 64 MiB, 2 passes': 11.8,
  'ML-KEM-768 keygen + encapsulate + decapsulate': 5865,
  'Hybrid X25519 + ML-KEM-768 keygen + encapsulate + decapsulate': 1858,
};
